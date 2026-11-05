# Unsafe product (fake)

A fake product that uses [`ykilcher/totally-harmless-model`](https://huggingface.co/ykilcher/totally-harmless-model),
a public demo repository whose `pytorch_model.bin` holds a malicious pickle. Every Hugging Face scanner
rates it critical. The
[`.github/workflows/reference-security-gate.yml`](../../.github/workflows/reference-security-gate.yml) workflow checks that
strict validation blocks this product. **Never run this code**: loading the model executes the pickle.
