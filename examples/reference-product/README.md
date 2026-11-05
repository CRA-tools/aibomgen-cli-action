# Reference product (fake)

A small, fake product repository used by the reference pipeline in
[`.github/workflows/reference-pipeline.yml`](../../.github/workflows/reference-pipeline.yml).
It references Hugging Face models the way real code does (a `transformers` pipeline with a
pinned revision, a `sentence-transformers` model, and a `base_model` key in a training config),
so the pipeline has models to discover, document, validate, merge, and sign. Nothing here is meant to run.
