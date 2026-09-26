//! Weight containers on disk (G163, ADR 0078): census a container file, and construct a container
//! file from a census and the file it was taken of. Files are streamed through bounded buffers; a
//! constructed container is written to a temporary sibling and published by rename, so a partial
//! file is never left under the requested name.

use adapter::weights::safetensors::{self, WeightError};
use atlas_core::weights::{WeightCensus, same_content, validate};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::Path;

fn io_error(e: WeightError) -> io::Error {
    match e {
        WeightError::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

/// The census of the SafeTensors container at `path`.
pub fn census_file(path: impl AsRef<Path>) -> io::Result<WeightCensus> {
    let mut reader = BufReader::new(File::open(path)?);
    safetensors::census(&mut reader).map_err(io_error)
}

/// What a construction produced and what verified it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ConstructionOutcome {
    pub source_digest: String,
    pub output: String,
    pub output_digest: String,
    pub bytes: u64,
    /// The output censused again holds the same tensors, metadata and payload digests.
    pub content_preserved: bool,
    pub preservation: atlas_core::weights::PreservationClass,
}

/// Censuses `source`, constructs the SafeTensors container its census describes at `out` (the
/// payload streamed from `source`, digests verified), then censuses the output and compares.
pub fn construct_file(
    source: impl AsRef<Path>,
    out: impl AsRef<Path>,
) -> io::Result<ConstructionOutcome> {
    let source = source.as_ref();
    let out = out.as_ref();
    let census = census_file(source)?;
    let problems = validate(&census);
    if !problems.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            problems.join("; "),
        ));
    }
    let temporary = out.with_extension("atlas-partial");
    let bytes = {
        let mut payload = BufReader::new(File::open(source)?);
        let mut writer = BufWriter::new(File::create(&temporary)?);
        let bytes = safetensors::construct(&census, &mut payload, &mut writer).map_err(io_error)?;
        writer.flush()?;
        bytes
    };
    fs::rename(&temporary, out)?;
    let again = census_file(out)?;
    Ok(ConstructionOutcome {
        source_digest: census.artifact_digest.clone(),
        output: out.display().to_string(),
        output_digest: again.artifact_digest.clone(),
        bytes,
        content_preserved: same_content(&census, &again),
        preservation: atlas_core::weights::PreservationClass::Lossless,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_container_file_is_censused_constructed_and_verified() {
        let dir = std::env::temp_dir().join(format!("atlas-weights-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let header = r#"{"w":{"dtype":"F16","shape":[2,2],"data_offsets":[0,8]}}"#;
        let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let source = dir.join("fixture.safetensors");
        fs::write(&source, &bytes).unwrap();
        let out = dir.join("built.safetensors");
        let outcome = construct_file(&source, &out).unwrap();
        assert!(outcome.content_preserved);
        assert_eq!(outcome.bytes, fs::metadata(&out).unwrap().len());
        assert!(!out.with_extension("atlas-partial").exists());
        // Rebuilding the rebuilt container reproduces it byte for byte.
        let twice = dir.join("twice.safetensors");
        let second = construct_file(&out, &twice).unwrap();
        assert_eq!(second.output_digest, outcome.output_digest);
        assert_eq!(fs::read(&out).unwrap(), fs::read(&twice).unwrap());
        // A malformed file is refused, never half-read.
        fs::write(&source, [0u8; 4]).unwrap();
        assert!(census_file(&source).is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
