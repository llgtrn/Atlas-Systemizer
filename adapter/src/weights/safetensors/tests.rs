use super::*;
use atlas_core::weights::{PreservationClass, same_content};
use std::io::Cursor;

/// A SafeTensors container with `header` (JSON text, as written) and `payload`.
fn container(header: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = (header.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload);
    out
}

/// A fixture as another producer might write it: keys unsorted, no padding, metadata last.
fn fixture() -> Vec<u8> {
    let payload: Vec<u8> = (0u8..40).collect();
    container(
        r#"{"model.layers.0.self_attn.q_proj.weight":{"dtype":"F32","shape":[2,3],"data_offsets":[0,24]},"embed":{"dtype":"BF16","shape":[4,2],"data_offsets":[24,40]},"__metadata__":{"format":"pt","producer":"fixture"}}"#,
        &payload,
    )
}

fn census_of(bytes: &[u8]) -> Result<WeightCensus, WeightError> {
    census(&mut Cursor::new(bytes))
}

fn refused(bytes: &[u8]) -> String {
    match census_of(bytes) {
        Err(WeightError::Malformed(why)) => why,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_container_is_censused_as_storage_and_its_roles_stay_unknown() {
    let bytes = fixture();
    let c = census_of(&bytes).unwrap();
    assert_eq!(validate(&c), Vec::<String>::new());
    assert_eq!(c.format, WeightFormat::SafeTensors);
    assert_eq!(
        c.artifact_digest,
        IntegrityDigest::of_bytes(&bytes).as_str()
    );
    assert_eq!(c.payload_bytes, 40);
    assert_eq!(c.metadata["producer"], "fixture");
    // Payload order, not name order.
    let names: Vec<&str> = c.tensors.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["model.layers.0.self_attn.q_proj.weight", "embed"]);
    assert_eq!(c.tensors[0].shape, [2, 3]);
    assert_eq!(c.tensors[1].dtype, TensorDtype::BF16);
    let payload: Vec<u8> = (0u8..40).collect();
    assert_eq!(
        c.tensors[1].digest,
        IntegrityDigest::of_bytes(&payload[24..40]).as_str()
    );
    // A name that reads like a query projection is still only a name.
    assert_eq!(c.roles, EpistemicStatus::Unknown);
}

#[test]
fn construction_is_mechanical_lossless_and_deterministic() {
    let source = fixture();
    let c = census_of(&source).unwrap();
    let mut built = Vec::new();
    let written = construct(&c, &mut Cursor::new(&source), &mut built).unwrap();
    assert_eq!(written, built.len() as u64);
    // The header is rebuilt from the census, not copied: canonical order, 8-byte padding.
    assert_ne!(built, source);
    let header_len = u64::from_le_bytes(built[..8].try_into().unwrap()) as usize;
    assert_eq!(header_len % 8, 0);
    assert!(built[8..8 + header_len].starts_with(b"{\"__metadata__\""));
    // Structural round trip: the same content, every payload byte identical.
    let again = census_of(&built).unwrap();
    assert!(same_content(&c, &again));
    assert_eq!(&built[8 + header_len..], &source[source.len() - 40..]);
    // Deterministic: constructing from the reconstruction reproduces it byte for byte.
    let mut twice = Vec::new();
    construct(&again, &mut Cursor::new(&built), &mut twice).unwrap();
    assert_eq!(twice, built);
    assert!(PreservationClass::Lossless.exact_reconstruction_claimable(false));
}

#[test]
fn construction_refuses_a_payload_that_is_not_the_one_censused() {
    let source = fixture();
    let c = census_of(&source).unwrap();
    let mut tampered = source.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut out = Vec::new();
    assert!(matches!(
        construct(&c, &mut Cursor::new(&tampered), &mut out),
        Err(WeightError::DigestMismatch(why)) if why.contains("embed")
    ));
    // A census that does not validate constructs nothing.
    let mut broken = c.clone();
    broken.tensors[0].payload.end += 1;
    assert!(matches!(
        construct(&broken, &mut Cursor::new(&source), &mut Vec::new()),
        Err(WeightError::Malformed(_))
    ));
}

#[test]
fn every_untrusted_header_claim_is_checked_before_it_is_believed() {
    let tensor = |dtype: &str, shape: &str, offsets: &str| {
        format!(r#"{{"t":{{"dtype":"{dtype}","shape":{shape},"data_offsets":{offsets}}}}}"#)
    };
    let four = [0u8; 4];
    // Length prefix: too short, a header-length bomb, a header past the end of the file.
    assert!(refused(&[1, 2, 3]).contains("8-byte"));
    let mut bomb = (u64::MAX).to_le_bytes().to_vec();
    bomb.extend_from_slice(b"{}");
    assert!(refused(&bomb).contains("exceeds"));
    let mut past = 64u64.to_le_bytes().to_vec();
    past.extend_from_slice(b"{}");
    assert!(refused(&past).contains("past the end"));
    // The header: UTF-8, one object, no duplicate key.
    assert!(refused(&[2, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe]).contains("UTF-8"));
    assert!(refused(&container("[1]", &[])).contains("one JSON object"));
    let dup = r#"{"t":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"t":{"dtype":"U8","shape":[1],"data_offsets":[1,2]}}"#;
    assert!(refused(&container(dup, &[0, 0])).contains("duplicate key"));
    // Tensor entries: dtype, fields, shape and offsets.
    assert!(refused(&container(&tensor("Q4_K", "[4]", "[0,4]"), &four)).contains("no known dtype"));
    let extra = r#"{"t":{"dtype":"U8","shape":[4],"data_offsets":[0,4],"code":"x"}}"#;
    assert!(refused(&container(extra, &four)).contains("unknown field"));
    assert!(
        refused(&container(&tensor("U8", "[-1]", "[0,4]"), &four)).contains("non-negative integer")
    );
    assert!(
        refused(&container(&tensor("U8", "[1.5]", "[0,4]"), &four))
            .contains("non-negative integer")
    );
    assert!(
        refused(&container(
            &tensor("F64", "[18446744073709551615,2]", "[0,4]"),
            &four
        ))
        .contains("overflows")
    );
    assert!(refused(&container(&tensor("U8", "[4]", "[0]"), &four)).contains("[start, end]"));
    assert!(refused(&container(&tensor("U8", "[4]", "[4,0]"), &four)).contains("end before start"));
    // Ranges: outside the payload, overlapping, leaving a hole, disagreeing with the shape.
    assert!(refused(&container(&tensor("U8", "[8]", "[0,8]"), &four)).contains("cover 8 of the 4"));
    let overlap = r#"{"a":{"dtype":"U8","shape":[3],"data_offsets":[0,3]},"b":{"dtype":"U8","shape":[3],"data_offsets":[1,4]}}"#;
    assert!(refused(&container(overlap, &four)).contains("overlap or leave a hole"));
    let hole = r#"{"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"b":{"dtype":"U8","shape":[2],"data_offsets":[2,4]}}"#;
    assert!(refused(&container(hole, &four)).contains("overlap or leave a hole"));
    assert!(
        refused(&container(&tensor("F32", "[2]", "[0,4]"), &four))
            .contains("holds not the 8 bytes")
    );
    // Metadata is strings only.
    let meta = r#"{"__metadata__":{"k":1}}"#;
    assert!(refused(&container(meta, &[])).contains("not a string"));
    // An empty container is a valid, empty census.
    let empty = census_of(&container("{}", &[])).unwrap();
    assert!(empty.tensors.is_empty());
}

#[test]
fn payloads_are_read_in_bounded_chunks() {
    // A tensor several chunks long digests and constructs through the chunked path.
    let payload: Vec<u8> = (0..(3 * CHUNK + 17)).map(|i| (i % 251) as u8).collect();
    let header = format!(
        r#"{{"big":{{"dtype":"U8","shape":[{}],"data_offsets":[0,{}]}}}}"#,
        payload.len(),
        payload.len()
    );
    let source = container(&header, &payload);
    let c = census_of(&source).unwrap();
    assert_eq!(
        c.tensors[0].digest,
        IntegrityDigest::of_bytes(&payload).as_str()
    );
    let mut built = Vec::new();
    construct(&c, &mut Cursor::new(&source), &mut built).unwrap();
    assert_eq!(&built[built.len() - payload.len()..], &payload[..]);
}

#[test]
fn a_constructed_header_is_padded_with_spaces_to_eight_bytes() {
    let mut unpadded = 0;
    for name in [
        "t", "tt", "ttt", "tttt", "ttttt", "tttttt", "ttttttt", "tttttttt",
    ] {
        let header = format!(r#"{{"{name}":{{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}}}"#);
        let c = census_of(&container(&header, &[7])).unwrap();
        let raw = serde_json::to_vec(&serde_json::json!({
            name: {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}
        }))
        .unwrap();
        let built = header_of(&c);
        assert_eq!(built.len() % 8, 0, "{name}");
        assert_eq!(&built[..raw.len()], &raw[..], "{name}");
        assert!(built[raw.len()..].iter().all(|b| *b == b' '), "{name}");
        unpadded += usize::from(!raw.len().is_multiple_of(8));
    }
    assert!(unpadded > 0, "some fixture needs padding");
}
