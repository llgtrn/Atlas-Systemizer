---
id: atlas.decision.0078.weight-artifacts-physical-census-and-mechanical-construction
type: decision
status: accepted
canonical: true
---
# ADR 0078 — Weight artifacts: a physical census and a mechanical construction, with roles left UNKNOWN (G163)

## Context

The owner directed an in-place upgrade: neural-network weight artifacts should become first-class Atlas artifacts. The directive has five parts:

- extend the existing artifact, census, construction, provenance and verification machinery, with no second subsystem and no pairwise converters;
- keep physical storage apart from semantic roles;
- construct mechanically, so the AI never writes bytes;
- keep lossless, reversible-with-retained and lossy transforms distinct;
- parse data only, with no pickle.

Before G163 a weight file was an opaque binary at L0, known by its extension and a digest (DEBT-ARTIFACT_SEMANTICS, ADR 0071).

The `.atlas` v1 contract is THIN: payloads stay outside the container and are referenced by digest. `.atlasx` is the executable projection of a SelectedDesign, not a payload store. `ORGANISM-MODEL-ADMISSION.md` already allows self-hosted weights as content-addressed artifacts, with activation as a separate admission event. A weight census therefore has to reference payloads by digest and byte range and never carry them.

The first slice is SafeTensors. It is the smallest format that is data-only by design: a u64 little-endian header length, a JSON header, and one contiguous byte buffer. It was implemented from its published format description. No donor source was materialized, and nothing was copied.

## Decision

1. **The physical layer is a typed census record** (`core::weights`, schema `atlas.weight-census.v1`). A `WeightCensus` carries:
   - the format;
   - the artifact digest and length;
   - where the payload starts and how long it is;
   - the free-form metadata;
   - one `PhysicalTensor` per tensor: its name, dtype (a vocabulary enum), shape, payload byte range and BLAKE3 digest.

   `validate` refuses a census that could not have come from a real artifact:
   - arithmetic overflow;
   - a range whose length is not dtype × shape;
   - overlapping ranges, or holes between them;
   - ranges that do not cover the payload exactly;
   - duplicate names;
   - malformed digests;
   - any claimed roles.
2. **Semantic roles are UNKNOWN, and a name is never a role.** `roles` is an `EpistemicStatus` that must be `UNKNOWN` in this slice. A tensor named `model.layers.0.attn.q.weight` is still only a name. Mapping a physical tensor to a semantic role (query projection, norm scale, quantization scale) needs structural evidence and is a later stage (W3).
3. **The census is streamed, bounded and read before it is trusted** (`adapter::weights::safetensors::census`):
   - the header length is bounded by `MAX_HEADER_BYTES` (100 MiB);
   - the JSON is parsed as data, rejecting duplicate keys, unknown fields, unknown dtypes and non-integer shapes or offsets;
   - the complete structure is checked before any payload byte is read;
   - the per-tensor digests and the artifact digest are then computed in 64 KiB chunks.

   Nothing is executed and no pickle is read. Memory is bounded by the header, not the payload. On a 1 GiB artifact the census peaked at about 14.6 MB resident memory, and construction at about 15.1 MB (`evidence/weights/G163-safetensors-oracle.json`).
4. **Construction is mechanical and verifies before it claims** (`construct`). The output is written from two inputs only:
   - the typed census record;
   - payload byte ranges read from the source and checked against each tensor's recorded digest.

   The header is rebuilt from the record, never copied: keys sorted, padded with spaces to 8 bytes. A digest mismatch refuses the output. `runtime::weights::construct_file` writes to a partial file and renames it only after the output's own census matches the source's content (`same_content`). The CLI is `weights census` and `weights construct`; on failure `weights construct` exits `WEIGHT_CONTENT_NOT_PRESERVED`.
5. **Preservation is a typed class.** `PreservationClass` is one of:
   - `LOSSLESS`;
   - `REVERSIBLE_WITH_RETAINED`, whose exact reconstruction is claimable only while the retained residual is present;
   - `LOSSY`.

   A re-encoding of SafeTensors to SafeTensors is `LOSSLESS`: the tensor contents, names, dtypes, shapes and metadata are equal. Byte identity is not claimed. The format does not fix the order of header keys, and Atlas writes its own canonical order.

## Consequences

- **Oracle.** The published reference implementation (`safetensors` 0.4.5 on PyPI, run as a black-box oracle in a scratch environment and never a dependency) wrote an artifact with:
  - 8 tensors across the F16, F32, F64, I64, I32, U8 and BOOL dtypes;
  - a scalar and an empty tensor;
  - metadata.

  Atlas censused it, and its constructed output was loaded back by the reference reader with every tensor and the metadata equal. The two files have the same length and differ only in header key order.

  Constructing again from Atlas's own output gives identical bytes: the canonical form is a fixed point.
- **Falsification.** All 12 mutants were killed:
  - the header bound dropped;
  - duplicate keys accepted;
  - unknown fields accepted;
  - a reversed range accepted;
  - the digest check skipped;
  - construction without validation;
  - the header padding dropped;
  - overlapping ranges accepted;
  - a payload not covered exactly;
  - duplicate names accepted;
  - a wrapping element count;
  - exact reconstruction claimed without the retained residual.
- **Maturity.** Physical census and lossless re-encoding of SafeTensors are EXPERIMENTAL and verified by tests and the oracle. The following remain unimplemented:
  - integration into the self census's typed record families and the support ladder (W2);
  - semantic role mapping (W3);
  - transforms such as quantization and sharding (W4);
  - any other format: GGUF, ONNX, PyTorch zip archives (never unpickled), MLX (W5).
- **Nothing absorbed, nothing extinct.** The weight donor families (ggml-org/llama.cpp, huggingface/safetensors, huggingface/transformers, pytorch/pytorch, onnx/onnx, ml-explore/mlx) enter the FULL_OSS_REPLAY ledger as explicitly authorized and NEVER_REPLAYED. Each is replayed one at a time, with its license verified at its pin.
- **Capability epoch E12.** Atlas can now census a weight artifact physically and reconstruct it mechanically, with content preservation verified. No processed donor's revalidation trigger concerns weights, so every verdict stays CURRENT.
