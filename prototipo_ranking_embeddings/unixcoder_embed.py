# -*- coding: utf-8 -*-
"""Code embeddings with UniXcoder (microsoft/unixcoder-base).

Uses the official `<encoder-only>` mode plus normalised mean pooling. Without the mode
tokens the cosine similarity degenerates -- a renamed clone scores below unrelated code
-- so the tokenisation here replicates UniXcoder's official wrapper.
"""
import warnings, torch
warnings.filterwarnings("ignore")
from transformers import AutoTokenizer, AutoModel

_MODEL = "microsoft/unixcoder-base"


class UniXcoder:
    def __init__(self, name=_MODEL, max_length=512):
        self.tok = AutoTokenizer.from_pretrained(name)
        self.model = AutoModel.from_pretrained(name)
        self.model.eval()
        self.max_length = max_length
        self.pad = self.tok.pad_token_id

    @torch.no_grad()
    def embed(self, code):
        t = self.tok.tokenize(code or " ")[: self.max_length - 4]
        t = [self.tok.cls_token, "<encoder-only>", self.tok.sep_token] + t + [self.tok.sep_token]
        ids = torch.tensor([self.tok.convert_tokens_to_ids(t)])
        mask = ids.ne(self.pad)
        o = self.model(ids, attention_mask=mask)
        v = (o[0] * mask.unsqueeze(-1)).sum(1) / mask.sum(-1, keepdim=True)
        return torch.nn.functional.normalize(v, p=2, dim=1).squeeze(0)


def cos(a, b):
    return float(a @ b)
