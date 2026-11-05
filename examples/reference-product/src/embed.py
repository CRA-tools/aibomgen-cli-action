from sentence_transformers import SentenceTransformer

model = SentenceTransformer("BAAI/bge-small-en-v1.5")


def embed(sentences: list[str]):
    return model.encode(sentences)
