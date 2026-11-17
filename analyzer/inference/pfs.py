"""Infer PFS on child SA rekeys from the size of the encrypted CREATE_CHILD_SA response.

A rekey with PFS carries a key exchange payload (8 + |g| bytes) and one more
transform in its SA payload (8 bytes). The exchange is encrypted, but its
length is not, and everything else in a rekey response has a size that is
either fixed or readable from cleartext:

=====================  ============================================  ==========
Payload                Size                                          Known from
=====================  ============================================  ==========
SA, one proposal       32 to 44 (+8 with a DH transform)             structure
Nonce                  4 + nonce length                              IKE_SA_INIT
TSi, TSr               8 + 16 (IPv4) or 8 + 40 (IPv6), each          IP version
Notifies               0 to 3 x 8 (USE_TRANSPORT_MODE and the like)  assumption
KE (PFS only)          8 + |g|                                       the question
=====================  ============================================  ==========

The response is used rather than the request: it carries one chosen proposal
and no REKEY_SA notify, so fewer sizes are unknown. The encrypted length gives
the plaintext to within one cipher block, which is the remaining uncertainty.
Where that window straddles the line, the answer is Unknown.

shortcut: assumes one traffic selector each way; a policy with several subnets
per side adds 16+ bytes per extra selector and could read as PFS. Upgrade by
modelling TS count once captures with multi-subnet policies exist.
"""

from __future__ import annotations

from analyzer.record import Attribute

METHOD = "create_child_sa_response_size"

#: IKE header plus the SK payload's generic header.
FIXED_HEADERS = 28 + 4

#: IKE encryption transform -> (IV bytes, padding block, ICV bytes if AEAD).
#: AEAD block is taken as 16, the widest, so the plaintext window never comes
#: out narrower than the truth.
IKE_ENCR = {
    "ENCR_AES_CBC": (16, 16, None),
    "ENCR_CAMELLIA_CBC": (16, 16, None),
    "ENCR_3DES": (8, 8, None),
    "ENCR_AES_GCM_8": (8, 16, 8),
    "ENCR_AES_GCM_12": (8, 16, 12),
    "ENCR_AES_GCM_16": (8, 16, 16),
    "ENCR_CHACHA20_POLY1305": (8, 16, 16),
}

#: IKE integrity transform -> ICV bytes.
IKE_INTEG_ICV = {
    "AUTH_HMAC_MD5_96": 12,
    "AUTH_HMAC_SHA1_96": 12,
    "AUTH_AES_XCBC_96": 12,
    "AUTH_AES_CMAC_96": 12,
    "AUTH_HMAC_SHA2_256_128": 16,
    "AUTH_HMAC_SHA2_384_192": 24,
    "AUTH_HMAC_SHA2_512_256": 32,
}

#: Key exchange group -> public value bytes (|g|).
KE_BYTES = {
    "MODP_1024": 128, "MODP_1536": 192, "MODP_2048": 256, "MODP_3072": 384,
    "MODP_4096": 512, "ECP_256": 64, "ECP_384": 96, "ECP_521": 132,
    "ECP_256_BP": 64, "ECP_384_BP": 96, "ECP_512_BP": 128,
    "CURVE_25519": 32, "CURVE_448": 56,
}

SA_MIN, SA_SPREAD = 32, 12      # one proposal: ENCR (+keylen), optional INTEG, ESN
NOTIFY_SPREAD = 3 * 8           # up to three 8-byte status notifies
PFS_EXTRA_MIN = 8 + 8 + min(KE_BYTES.values())   # DH transform + KE header + smallest group

CONFIDENCE = 0.9


def classify_response(length: int, iv: int, block: int, icv: int,
                      nonce_len: int, ip_version: int) -> tuple[bool | None, list[str]]:
    """PFS verdict for one rekey response, and the groups its size fits.

    Returns (True, groups), (False, []), or (None, []) when the size could be
    either.
    """
    encrypted = length - FIXED_HEADERS - iv - icv
    plain_lo, plain_hi = encrypted - block, encrypted - 1
    ts = 8 + (16 if ip_version == 4 else 40)
    base = SA_MIN + 4 + nonce_len + 2 * ts
    no_ke_max = base + SA_SPREAD + NOTIFY_SPREAD

    if plain_hi < base + PFS_EXTRA_MIN:
        return False, []
    if plain_lo > no_ke_max:
        g_lo, g_hi = plain_lo - no_ke_max - 16, plain_hi - base - 16
        return True, sorted(g for g, n in KE_BYTES.items() if g_lo <= n <= g_hi)
    return None, []


def infer_pfs(response_lengths: list[int], *, encr: str | None, integ: str | None,
              nonce_len: int | None, ip_version: int) -> Attribute:
    """PFS on child SA rekeys, from every rekey response in the capture."""
    if not response_lengths:
        return Attribute.unknown(
            "no child SA rekey was captured, so there is no rekey exchange to size",
            resolvable_by="longer_capture",
        )
    structure = IKE_ENCR.get(encr or "")
    if structure is None or nonce_len is None:
        return Attribute.unknown(
            f"the IKE SA cipher ({encr or 'not captured'}) or nonce length is not known, "
            "so the encrypted rekey size cannot be decoded",
            resolvable_by="not_resolvable",
        )
    iv, block, aead_icv = structure
    icv = aead_icv if aead_icv is not None else IKE_INTEG_ICV.get(integ or "")
    if icv is None:
        return Attribute.unknown(f"unrecognised IKE integrity {integ}",
                                 resolvable_by="not_resolvable")

    verdicts = [classify_response(n, iv, block, icv, nonce_len, ip_version)
                for n in response_lengths]
    answers = {v for v, _ in verdicts}
    features = {"rekey_responses": len(response_lengths),
                "response_bytes": ",".join(str(n) for n in sorted(set(response_lengths))),
                "ike_nonce_bytes": nonce_len}

    if answers == {False}:
        return Attribute.inferred(
            False, CONFIDENCE, METHOD, features=features,
            note="every child SA rekey response is too small to hold a key exchange payload",
        )
    if answers == {True}:
        groups = sorted(set.intersection(*(set(g) for _, g in verdicts)))
        features["key_exchange_groups_fitting"] = ",".join(groups) or "none of the known groups"
        return Attribute.inferred(
            True, CONFIDENCE, METHOD, features=features,
            note="every child SA rekey response is too large to lack a key exchange "
            f"payload; its size fits {', '.join(groups) or 'no known group'}",
        )
    return Attribute.unknown(
        "the rekey response sizes fall where a response with and without a key "
        f"exchange overlap, or disagree between rekeys (sizes {features['response_bytes']})",
        resolvable_by="supply_keys",
    )
