from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

# Pinned to a commit of the Hub repository, so the AIBOM pins it too.
model = AutoModelForSequenceClassification.from_pretrained(
    "distilbert/distilbert-base-uncased-finetuned-sst-2-english",
    revision="714eb0fa89d2f80546fda750413ed43d93601a13",
)
tokenizer = AutoTokenizer.from_pretrained(model.name_or_path)
classifier = pipeline("text-classification", model=model, tokenizer=tokenizer)


def classify(text: str) -> dict:
    return classifier(text)[0]
