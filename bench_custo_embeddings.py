# -*- coding: utf-8 -*-
"""Cost micro-benchmark of the semantic layer: what one fork x CVE pair costs.

Measures model load time and per-window embedding time, then projects the cost of the
whole ecosystem run. Used to support the scalability claim in the paper. CPU-only by
default; batching and GPU are unmeasured optimisations.
"""
import io, sys, time, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "prototipo_ranking_embeddings"))

t0 = time.perf_counter()
from unixcoder_embed import UniXcoder as Embedder
m = Embedder()
t_load = time.perf_counter() - t0
print(f"carga do modelo (1x por execucao): {t_load:.1f}s")

# janela tipica: 16 linhas de codigo
janela = "\n".join([
    "    def _handle_upload(self, request, user_id):",
    "        body = parse_json_object_from_request(request)",
    "        validate_json_object(body, self.KeyUploadRequestBody)",
    "        if user_id not in self.store.get_users():",
    "            raise SynapseError(400, 'unknown user')",
    "        for key_id, key in body.get('one_time_keys', {}).items():",
    "            if not isinstance(key, dict):",
    "                continue",
    "            self.store.add_key(user_id, key_id, key)",
    "        result = yield self.handler.upload_keys_for_user(",
    "            user_id, device_id, body",
    "        )",
    "        return 200, result",
    "    # end of handler",
    "",
    "",
])

N = 40
t0 = time.perf_counter()
for i in range(N):
    m.embed(janela + f"\n# {i}")
dt = time.perf_counter() - t0
per = dt / N
print(f"embedding de 1 janela (16 linhas, CPU): {per*1000:.0f} ms  ({N} janelas em {dt:.1f}s)")
for w in (20, 60, 160):
    print(f"  par fork x CVE com {w:3d} janelas + 2 referencias: {per*(w+2):.1f}s de GPU/CPU")
print()
print("projecao (so a camada semantica, sem rede):")
for pares in (43, 500, 5000):
    print(f"  {pares:5d} pares x ~60 janelas: {per*62*pares/60:.1f} min")
