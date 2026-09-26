---
id: atlas.contract.organism-model-admission
type: contract
status: active
canonical: true
---
# Organism Model and Weight Admission Contract

Models and weights are replaceable capability artifacts inside a Digital Organism.

## Model artifact identity

Each model/checkpoint records:

- ModelDefinitionId;
- architecture and tokenizer/representation identity where applicable;
- base lineage;
- training dataset/compiler identity;
- training configuration;
- checkpoint hash;
- evaluation evidence;
- hardware/runtime compatibility;
- safety/regression results;
- Genome compatibility;
- temporal activation interval.

## Admission pipeline

```text
candidate model / weights
  ↓
integrity + provenance
  ↓
offline evaluation
  ↓
task/regression evaluation
  ↓
simulation / sandbox
  ↓
resource/homeostasis evaluation
  ↓
Genome compatibility
  ↓
authority/policy admission
  ↓
ACTIVE binding
```

No candidate model may become active solely because training completed or a provider returned a newer model.

## External API models

External model APIs are admitted as capability-provider bindings with provider/model/version/policy/context-disclosure metadata. Their hidden weights are not Atlas canonical artifacts.

## Self-hosted models

Self-hosted model weights may be content-addressed Atlas artifacts/shards. Activation remains a separate admission event. Their physical census, mechanical construction and preservation classes are defined in `UNIVERSAL-ENGINEERING-WORLD.md` (Weight artifacts, ADR 0078); a census never makes weights active.

## Hybrid organisms

Different organs may use different providers/models. For example perception may be local, language reasoning external, planner deterministic and policy model self-hosted.

## Rollback

Every activation creates a recoverable previous binding unless explicitly prohibited by retention policy. Drift, regression, resource pressure or incompatibility may trigger bounded rollback.
