//! SafeTensors census and construction (G163, ADR 0078): the first weight container format.
//!
//! The container is `u64 LE header length N`, `N` bytes of a JSON object, then the payload. The
//! object maps each tensor name to `{dtype, shape, data_offsets: [start, end]}` (offsets into the
//! payload) and may carry `__metadata__`, a string-to-string map. Parsing is data-only: the header
//! is JSON, nothing is executed or deserialized into code (the unlike of pickle checkpoints).
//!
//! Everything the header claims is checked before it is believed: the header length is bounded
//! and inside the file; the JSON is one object without duplicate keys; every dtype is known; an
//! element count or byte size that overflows is refused; the ranges must tile the payload exactly
//! (no overlap, no hole, nothing outside). Payloads are read in bounded chunks to digest them.
//!
//! Construction is mechanical: the header is rebuilt from the typed census alone (canonical key
//! order, padded with spaces to 8 bytes), and each tensor's payload is streamed from a payload
//! source by its range, its digest verified while it is copied. No byte of the output is taken
//! from the source's header.

use atlas_core::EpistemicStatus;
use atlas_core::identity::{IntegrityDigest, blake3};
use atlas_core::weights::{
    PayloadRange, PhysicalTensor, TensorDtype, WEIGHT_CENSUS_SCHEMA, WeightCensus, WeightFormat,
    expected_bytes, validate,
};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};

/// The largest header this reader accepts (the format's own bound on header size).
pub const MAX_HEADER_BYTES: u64 = 100 * 1024 * 1024;
/// Chunk size of every payload read: memory stays bounded whatever the tensor size.
const CHUNK: usize = 64 * 1024;

#[derive(Debug)]
pub enum WeightError {
    Io(io::Error),
    /// The container is not a well-formed SafeTensors file; the reason says what was refused.
    Malformed(String),
    /// A payload read during construction does not hash to the census's digest.
    DigestMismatch(String),
}

impl fmt::Display for WeightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Malformed(why) => write!(f, "WEIGHT_CONTAINER_MALFORMED: {why}"),
            Self::DigestMismatch(why) => write!(f, "WEIGHT_PAYLOAD_DIGEST_MISMATCH: {why}"),
        }
    }
}

impl From<io::Error> for WeightError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn malformed<T>(why: impl Into<String>) -> Result<T, WeightError> {
    Err(WeightError::Malformed(why.into()))
}

/// The header's JSON object with its keys in file order, refusing a duplicate key (a JSON parser
/// that keeps the last one would let two tensors share a name unseen).
struct Entries(Vec<(String, serde_json::Value)>);

impl<'de> serde::Deserialize<'de> for Entries {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = Entries;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Entries, A::Error> {
                let mut out: Vec<(String, serde_json::Value)> = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if out.iter().any(|(k, _)| *k == key) {
                        return Err(serde::de::Error::custom(format!("duplicate key `{key}`")));
                    }
                    out.push((key, value));
                }
                Ok(Entries(out))
            }
        }
        d.deserialize_map(Visit)
    }
}

/// BLAKE3 of `len` bytes read from `reader` in bounded chunks.
fn digest_stream(reader: &mut impl Read, len: u64) -> Result<String, WeightError> {
    let mut hasher = blake3::Hasher::new();
    let mut left = len;
    let mut buf = vec![0u8; CHUNK];
    while left > 0 {
        let n = (left.min(CHUNK as u64)) as usize;
        reader.read_exact(&mut buf[..n])?;
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(IntegrityDigest::blake3_256(&hasher.finalize())
        .as_str()
        .to_owned())
}

/// Censuses the SafeTensors container `reader`: its tensors' storage facts and digests, its
/// metadata, and the container's own digest. Only the header and bounded payload chunks are read.
pub fn census(reader: &mut (impl Read + Seek)) -> Result<WeightCensus, WeightError> {
    let artifact_bytes = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;
    if artifact_bytes < 8 {
        return malformed("shorter than the 8-byte header length");
    }
    let mut len = [0u8; 8];
    reader.read_exact(&mut len)?;
    let header_len = u64::from_le_bytes(len);
    if header_len > MAX_HEADER_BYTES {
        return malformed(format!(
            "header length {header_len} exceeds {MAX_HEADER_BYTES}"
        ));
    }
    let Some(payload_bytes) = artifact_bytes.checked_sub(8 + header_len) else {
        return malformed(format!(
            "header length {header_len} runs past the end of the file"
        ));
    };
    let mut header = vec![0u8; header_len as usize];
    reader.read_exact(&mut header)?;
    let Ok(text) = std::str::from_utf8(&header) else {
        return malformed("header is not UTF-8");
    };
    let entries: Entries = match serde_json::from_str(text) {
        Ok(entries) => entries,
        Err(e) => return malformed(format!("header is not one JSON object: {e}")),
    };
    let mut metadata = BTreeMap::new();
    let mut tensors = Vec::new();
    for (name, value) in entries.0 {
        if name.as_str() == "__metadata__" {
            let Some(map) = value.as_object() else {
                return malformed("__metadata__ is not an object");
            };
            for (k, v) in map {
                let Some(v) = v.as_str() else {
                    return malformed(format!("__metadata__ value `{k}` is not a string"));
                };
                metadata.insert(k.clone(), v.to_owned());
            }
            continue;
        }
        tensors.push(tensor_entry(&name, &value)?);
    }
    tensors.sort_by_key(|t: &PhysicalTensor| (t.payload, t.name.clone()));
    let payload_offset = 8 + header_len;
    let mut census = WeightCensus {
        schema: WEIGHT_CENSUS_SCHEMA.into(),
        format: WeightFormat::SafeTensors,
        artifact_digest: String::new(),
        artifact_bytes,
        payload_offset,
        payload_bytes,
        metadata,
        tensors,
        roles: EpistemicStatus::Unknown,
        roles_basis: "a physical census names storage only; no architecture mapping proves a tensor's semantic role (stage 5)".into(),
    };
    // Structure first: nothing is read from a range the header has not been checked to hold.
    let structural: Vec<String> = validate(&census)
        .into_iter()
        .filter(|p| !p.contains("malformed digest"))
        .collect();
    if !structural.is_empty() {
        return malformed(structural.join("; "));
    }
    for t in &mut census.tensors {
        reader.seek(SeekFrom::Start(payload_offset + t.payload.start))?;
        t.digest = digest_stream(reader, t.payload.end - t.payload.start)?;
    }
    reader.seek(SeekFrom::Start(0))?;
    census.artifact_digest = digest_stream(reader, artifact_bytes)?;
    Ok(census)
}

fn tensor_entry(name: &str, value: &serde_json::Value) -> Result<PhysicalTensor, WeightError> {
    let Some(fields) = value.as_object() else {
        return malformed(format!("tensor `{name}` is not an object"));
    };
    if let Some(extra) = fields
        .keys()
        .find(|k| !matches!(k.as_str(), "dtype" | "shape" | "data_offsets"))
    {
        return malformed(format!("tensor `{name}` carries unknown field `{extra}`"));
    }
    let Some(dtype) = fields
        .get("dtype")
        .filter(|d| d.is_string())
        .and_then(|d| serde_json::from_value::<TensorDtype>(d.clone()).ok())
    else {
        return malformed(format!("tensor `{name}` has no known dtype"));
    };
    let integers = |key: &str| -> Result<Vec<u64>, WeightError> {
        let Some(items) = fields.get(key).and_then(|v| v.as_array()) else {
            return malformed(format!("tensor `{name}` has no `{key}` array"));
        };
        items
            .iter()
            .map(|i| {
                i.as_u64().ok_or_else(|| {
                    WeightError::Malformed(format!(
                        "tensor `{name}`: `{key}` holds a value that is not a non-negative integer"
                    ))
                })
            })
            .collect()
    };
    let shape = integers("shape")?;
    let offsets = integers("data_offsets")?;
    let [start, end] = offsets[..] else {
        return malformed(format!("tensor `{name}`: data_offsets is not [start, end]"));
    };
    if end < start {
        return malformed(format!("tensor `{name}`: data_offsets end before start"));
    }
    if expected_bytes(dtype, &shape).is_none() {
        return malformed(format!("tensor `{name}`: element count overflows"));
    }
    Ok(PhysicalTensor {
        name: name.to_owned(),
        dtype,
        shape,
        payload: PayloadRange { start, end },
        digest: String::new(),
    })
}

/// The header a census constructs: one JSON object, `__metadata__` (when present) and the
/// tensors in canonical (sorted) key order, padded with spaces to a multiple of 8 bytes.
pub fn header_of(census: &WeightCensus) -> Vec<u8> {
    let mut object = serde_json::Map::new();
    if !census.metadata.is_empty() {
        object.insert(
            "__metadata__".into(),
            serde_json::to_value(&census.metadata).expect("a string map serializes"),
        );
    }
    for t in &census.tensors {
        object.insert(
            t.name.clone(),
            serde_json::json!({
                "dtype": t.dtype.as_str(),
                "shape": t.shape,
                "data_offsets": [t.payload.start, t.payload.end],
            }),
        );
    }
    let mut header =
        serde_json::to_vec(&serde_json::Value::Object(object)).expect("a JSON value serializes");
    while !header.len().is_multiple_of(8) {
        header.push(b' ');
    }
    header
}

/// Writes the SafeTensors container `census` describes to `out`: the header built from the census,
/// then every tensor's payload streamed from `payload`, the container the census was taken of
/// (read only at the census's payload ranges), each range's digest verified while it is copied.
/// Returns the bytes written. Refuses a census that does not validate.
pub fn construct(
    census: &WeightCensus,
    payload: &mut (impl Read + Seek),
    out: &mut impl Write,
) -> Result<u64, WeightError> {
    let problems = validate(census);
    if !problems.is_empty() {
        return malformed(problems.join("; "));
    }
    let header = header_of(census);
    out.write_all(&(header.len() as u64).to_le_bytes())?;
    out.write_all(&header)?;
    let mut written = 8 + header.len() as u64;
    let mut buf = vec![0u8; CHUNK];
    for t in &census.tensors {
        payload.seek(SeekFrom::Start(census.payload_offset + t.payload.start))?;
        let mut hasher = blake3::Hasher::new();
        let mut left = t.payload.end - t.payload.start;
        while left > 0 {
            let n = (left.min(CHUNK as u64)) as usize;
            payload.read_exact(&mut buf[..n])?;
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            left -= n as u64;
        }
        let digest = IntegrityDigest::blake3_256(&hasher.finalize());
        if digest.as_str() != t.digest {
            return Err(WeightError::DigestMismatch(format!(
                "tensor `{}` read {} where the census recorded {}",
                t.name,
                digest.as_str(),
                t.digest
            )));
        }
        written += t.payload.end - t.payload.start;
    }
    Ok(written)
}

#[cfg(test)]
mod tests;
