# DO NOT RUN: the weights of this model contain a malicious pickle.
from transformers import AutoModel

model = AutoModel.from_pretrained("ykilcher/totally-harmless-model")
