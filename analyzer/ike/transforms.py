"""IANA registries for IKE, and the structural facts that follow from them.

Two kinds of knowledge live here, and the split is deliberate:

* **Names.** Numeric transform IDs to canonical names, from the IANA registries
  for IKEv2 parameters and for ISAKMP. Pure lookup.
* **Structure.** Facts that follow from the algorithm itself, such as the block
  size of AES-CBC or whether a transform is AEAD. These are protocol facts, not
  opinions, so they belong beside the names.

What does **not** live here is policy. Whether 3DES is acceptable is a judgement
against a standards baseline, and that belongs in the rule catalogue
(``analyzer/rules/catalogue/``) where it can cite its source. Keeping the two
apart is what lets the baseline be re-tuned without touching the parser.

Unknown IDs are never dropped. They render as ``ENCR_UNKNOWN_99`` so equipment
the parser has not met still shows up in a report rather than vanishing.
"""

from __future__ import annotations

from typing import Final

# --------------------------------------------------------------- IKEv2 basics

#: IKEv2 exchange types (RFC 7296 section 3.1, plus later extensions).
EXCHANGE_TYPES_V2: Final[dict[int, str]] = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME",
    39: "GSA_AUTH",
    40: "GSA_REGISTRATION",
    41: "GSA_REKEY",
    43: "IKE_INTERMEDIATE",
    44: "IKE_FOLLOWUP_KE",
}

#: IKEv2 payload types (RFC 7296 section 3.2).
PAYLOAD_TYPES_V2: Final[dict[int, str]] = {
    0: "NONE",
    33: "SA",
    34: "KE",
    35: "IDi",
    36: "IDr",
    37: "CERT",
    38: "CERTREQ",
    39: "AUTH",
    40: "NONCE",
    41: "NOTIFY",
    42: "DELETE",
    43: "VENDOR_ID",
    44: "TSi",
    45: "TSr",
    46: "SK",
    47: "CP",
    48: "EAP",
    49: "GSPM",
    50: "IDg",
    51: "GSA",
    52: "KD",
    53: "SKF",
    54: "PS",
}

#: Protocol IDs inside an SA payload.
PROTOCOL_IDS: Final[dict[int, str]] = {1: "IKE", 2: "AH", 3: "ESP", 4: "FC_ESP_HEADER"}

#: IKEv2 transform types (RFC 7296 section 3.3.2). Types 6 to 12 are the
#: additional key exchanges added by RFC 9370.
TRANSFORM_TYPES: Final[dict[int, str]] = {
    1: "ENCR",
    2: "PRF",
    3: "INTEG",
    4: "DH",
    5: "ESN",
    6: "ADDKE1",
    7: "ADDKE2",
    8: "ADDKE3",
    9: "ADDKE4",
    10: "ADDKE5",
    11: "ADDKE6",
    12: "ADDKE7",
}

TRANSFORM_ENCR: Final[int] = 1
TRANSFORM_PRF: Final[int] = 2
TRANSFORM_INTEG: Final[int] = 3
TRANSFORM_DH: Final[int] = 4
TRANSFORM_ESN: Final[int] = 5

#: Transform attribute types. Only key length is defined in practice.
TRANSFORM_ATTR_KEY_LENGTH: Final[int] = 14

# ------------------------------------------------------------------ registries

#: Transform type 1, encryption algorithms.
ENCR: Final[dict[int, str]] = {
    1: "ENCR_DES_IV64",
    2: "ENCR_DES",
    3: "ENCR_3DES",
    4: "ENCR_RC5",
    5: "ENCR_IDEA",
    6: "ENCR_CAST",
    7: "ENCR_BLOWFISH",
    8: "ENCR_3IDEA",
    9: "ENCR_DES_IV32",
    11: "ENCR_NULL",
    12: "ENCR_AES_CBC",
    13: "ENCR_AES_CTR",
    14: "ENCR_AES_CCM_8",
    15: "ENCR_AES_CCM_12",
    16: "ENCR_AES_CCM_16",
    18: "ENCR_AES_GCM_8",
    19: "ENCR_AES_GCM_12",
    20: "ENCR_AES_GCM_16",
    21: "ENCR_NULL_AUTH_AES_GMAC",
    23: "ENCR_CAMELLIA_CBC",
    24: "ENCR_CAMELLIA_CTR",
    25: "ENCR_CAMELLIA_CCM_8",
    26: "ENCR_CAMELLIA_CCM_12",
    27: "ENCR_CAMELLIA_CCM_16",
    28: "ENCR_CHACHA20_POLY1305",
    29: "ENCR_AES_CCM_8_IIV",
    30: "ENCR_AES_GCM_16_IIV",
    31: "ENCR_CHACHA20_POLY1305_IIV",
    32: "ENCR_KUZNYECHIK_MGM_KTREE",
    33: "ENCR_MAGMA_MGM_KTREE",
    34: "ENCR_KUZNYECHIK_MGM_MAC_KTREE",
    35: "ENCR_MAGMA_MGM_MAC_KTREE",
}

#: Transform type 2, pseudo-random functions.
PRF: Final[dict[int, str]] = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
    8: "PRF_AES128_CMAC",
    9: "PRF_HMAC_STREEBOG_512",
}

#: Transform type 3, integrity algorithms.
INTEG: Final[dict[int, str]] = {
    0: "AUTH_NONE",
    1: "AUTH_HMAC_MD5_96",
    2: "AUTH_HMAC_SHA1_96",
    3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5",
    5: "AUTH_AES_XCBC_96",
    6: "AUTH_HMAC_MD5_128",
    7: "AUTH_HMAC_SHA1_160",
    8: "AUTH_AES_CMAC_96",
    9: "AUTH_AES_128_GMAC",
    10: "AUTH_AES_192_GMAC",
    11: "AUTH_AES_256_GMAC",
    12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

#: Transform type 4, key exchange (Diffie-Hellman) groups.
DH_GROUPS: Final[dict[int, str]] = {
    0: "NONE",
    1: "MODP_768",
    2: "MODP_1024",
    5: "MODP_1536",
    14: "MODP_2048",
    15: "MODP_3072",
    16: "MODP_4096",
    17: "MODP_6144",
    18: "MODP_8192",
    19: "ECP_256",
    20: "ECP_384",
    21: "ECP_521",
    22: "MODP_1024_POS_160",
    23: "MODP_2048_POS_224",
    24: "MODP_2048_POS_256",
    25: "ECP_192",
    26: "ECP_224",
    27: "BRAINPOOL_P224R1",
    28: "BRAINPOOL_P256R1",
    29: "BRAINPOOL_P384R1",
    30: "BRAINPOOL_P512R1",
    31: "CURVE25519",
    32: "CURVE448",
    33: "GOST3410_2012_256",
    34: "GOST3410_2012_512",
    35: "ML_KEM_512",
    36: "ML_KEM_768",
    37: "ML_KEM_1024",
}

#: Transform type 5, extended sequence numbers.
ESN: Final[dict[int, str]] = {0: "NO_ESN", 1: "ESN"}

#: Approximate classical security strength in bits of each key exchange group.
#: Used by the DH rules and by the record-now-decrypt-later row of the threat
#: matrix. MODP figures follow the usual number-field-sieve cost estimates, so
#: they are indicative rather than exact.
DH_GROUP_STRENGTH_BITS: Final[dict[int, int]] = {
    1: 64,
    2: 80,
    5: 89,
    14: 112,
    15: 128,
    16: 152,
    17: 176,
    18: 200,
    19: 128,
    20: 192,
    21: 256,
    22: 80,
    23: 112,
    24: 112,
    25: 96,
    26: 112,
    27: 112,
    28: 128,
    29: 192,
    30: 256,
    31: 128,
    32: 224,
}

#: Groups that are post-quantum key encapsulation mechanisms rather than
#: classical Diffie-Hellman. Relevant to rule PQ-001.
PQ_DH_GROUPS: Final[frozenset[int]] = frozenset({35, 36, 37})

# --------------------------------------------------------- IKEv2 notifications

NOTIFY_TYPES: Final[dict[int, str]] = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD",
    4: "INVALID_IKE_SPI",
    5: "INVALID_MAJOR_VERSION",
    7: "INVALID_SYNTAX",
    9: "INVALID_MESSAGE_ID",
    11: "INVALID_SPI",
    14: "NO_PROPOSAL_CHOSEN",
    17: "INVALID_KE_PAYLOAD",
    24: "AUTHENTICATION_FAILED",
    34: "SINGLE_PAIR_REQUIRED",
    35: "NO_ADDITIONAL_SAS",
    36: "INTERNAL_ADDRESS_FAILURE",
    37: "FAILED_CP_REQUIRED",
    38: "TS_UNACCEPTABLE",
    39: "INVALID_SELECTORS",
    40: "UNACCEPTABLE_ADDRESSES",
    41: "UNEXPECTED_NAT_DETECTED",
    43: "TEMPORARY_FAILURE",
    44: "CHILD_SA_NOT_FOUND",
    45: "INVALID_GROUP_ID",
    46: "AUTHORIZATION_FAILED",
    47: "STATE_NOT_FOUND",
    16384: "INITIAL_CONTACT",
    16385: "SET_WINDOW_SIZE",
    16386: "ADDITIONAL_TS_POSSIBLE",
    16387: "IPCOMP_SUPPORTED",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE",
    16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED",
    16393: "REKEY_SA",
    16394: "ESP_TFC_PADDING_NOT_SUPPORTED",
    16395: "NON_FIRST_FRAGMENTS_ALSO",
    16396: "MOBIKE_SUPPORTED",
    16397: "ADDITIONAL_IP4_ADDRESS",
    16398: "ADDITIONAL_IP6_ADDRESS",
    16399: "NO_ADDITIONAL_ADDRESSES",
    16400: "UPDATE_SA_ADDRESSES",
    16401: "COOKIE2",
    16402: "NO_NATS_ALLOWED",
    16403: "AUTH_LIFETIME",
    16404: "MULTIPLE_AUTH_SUPPORTED",
    16405: "ANOTHER_AUTH_FOLLOWS",
    16406: "REDIRECT_SUPPORTED",
    16407: "REDIRECT",
    16408: "REDIRECTED_FROM",
    16409: "TICKET_LT_OPAQUE",
    16410: "TICKET_REQUEST",
    16411: "TICKET_ACK",
    16412: "TICKET_NACK",
    16413: "TICKET_OPAQUE",
    16414: "LINK_ID",
    16415: "USE_WESP_MODE",
    16416: "ROHC_SUPPORTED",
    16417: "EAP_ONLY_AUTHENTICATION",
    16418: "CHILDLESS_IKEV2_SUPPORTED",
    16419: "QUICK_CRASH_DETECTION",
    16420: "IKEV2_MESSAGE_ID_SYNC_SUPPORTED",
    16421: "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED",
    16422: "IKEV2_MESSAGE_ID_SYNC",
    16423: "IPSEC_REPLAY_COUNTER_SYNC",
    16424: "SECURE_PASSWORD_METHODS",
    16425: "PSK_PERSIST",
    16426: "PSK_CONFIRM",
    16427: "ERX_SUPPORTED",
    16428: "IFOM_CAPABILITY",
    16429: "SENDER_REQUEST_ID",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED",
    16431: "SIGNATURE_HASH_ALGORITHMS",
    16432: "CLONE_IKE_SA_SUPPORTED",
    16433: "CLONE_IKE_SA",
    16434: "PUZZLE",
    16435: "USE_PPK",
    16436: "PPK_IDENTITY",
    16437: "NO_PPK_AUTH",
    16438: "INTERMEDIATE_EXCHANGE_SUPPORTED",
    16439: "IP4_ALLOWED",
    16440: "IP6_ALLOWED",
    16441: "ADDITIONAL_KEY_EXCHANGE",
    16442: "USE_PPK_INT",
}

#: Notifications that signal NAT traversal detection (RFC 7296 section 3.10.1).
NAT_DETECTION_NOTIFIES: Final[frozenset[int]] = frozenset({16388, 16389})

#: Notifications that signal some post-quantum protection is on offer, read by
#: rule PQ-001. USE_PPK and its relatives are the RFC 8784 post-quantum
#: pre-shared keys. ADDITIONAL_KEY_EXCHANGE is the RFC 9370 multiple key
#: exchange mechanism, which rides on the RFC 9242 intermediate exchange.
PQ_NOTIFIES: Final[dict[int, str]] = {
    16435: "RFC 8784 post-quantum pre-shared key (USE_PPK)",
    16436: "RFC 8784 post-quantum pre-shared key identity",
    16437: "RFC 8784 post-quantum pre-shared key, PPK not mandatory",
    16438: "RFC 9242 intermediate exchange, prerequisite for RFC 9370",
    16441: "RFC 9370 additional key exchange",
    16442: "RFC 8784 post-quantum pre-shared key for intermediate exchange",
}

#: Signals that IKEv2 fragmentation (RFC 7383) is supported. Worth recording
#: because fragmented handshakes are a common reason a parser sees less than it
#: should, and a noted gap beats a silent one.
NOTIFY_FRAGMENTATION_SUPPORTED: Final[int] = 16430

# ------------------------------------------------------------- IKEv1 registries

#: IKEv1 exchange types (RFC 2408 section 3.1).
EXCHANGE_TYPES_V1: Final[dict[int, str]] = {
    0: "NONE",
    1: "BASE",
    2: "IDENTITY_PROTECTION",
    3: "AUTHENTICATION_ONLY",
    4: "AGGRESSIVE",
    5: "INFORMATIONAL",
    32: "QUICK_MODE",
    33: "NEW_GROUP_MODE",
}

#: Main Mode is exchange type 2, Aggressive Mode is 4. Aggressive Mode exposes
#: peer identities in cleartext, which is itself a finding (rule IKE-002).
EXCHANGE_MAIN_MODE: Final[int] = 2
EXCHANGE_AGGRESSIVE_MODE: Final[int] = 4

#: IKEv1 Phase 1 SA attribute classes (RFC 2409 appendix A).
IKEV1_ATTR_CLASSES: Final[dict[int, str]] = {
    1: "Encryption-Algorithm",
    2: "Hash-Algorithm",
    3: "Authentication-Method",
    4: "Group-Description",
    5: "Group-Type",
    6: "Group-Prime",
    7: "Group-Generator-One",
    8: "Group-Generator-Two",
    9: "Group-Curve-A",
    10: "Group-Curve-B",
    11: "Life-Type",
    12: "Life-Duration",
    13: "PRF",
    14: "Key-Length",
    15: "Field-Size",
    16: "Group-Order",
}

IKEV1_ATTR_ENCRYPTION: Final[int] = 1
IKEV1_ATTR_HASH: Final[int] = 2
IKEV1_ATTR_AUTH_METHOD: Final[int] = 3
IKEV1_ATTR_GROUP: Final[int] = 4
IKEV1_ATTR_LIFE_TYPE: Final[int] = 11
IKEV1_ATTR_LIFE_DURATION: Final[int] = 12
IKEV1_ATTR_KEY_LENGTH: Final[int] = 14

IKEV1_ENCR: Final[dict[int, str]] = {
    1: "DES_CBC",
    2: "IDEA_CBC",
    3: "BLOWFISH_CBC",
    4: "RC5_R16_B64_CBC",
    5: "3DES_CBC",
    6: "CAST_CBC",
    7: "AES_CBC",
    8: "CAMELLIA_CBC",
}

IKEV1_HASH: Final[dict[int, str]] = {
    1: "MD5",
    2: "SHA1",
    3: "TIGER",
    4: "SHA2_256",
    5: "SHA2_384",
    6: "SHA2_512",
}

#: IKEv1 authentication methods. Unlike IKEv2, this is a cleartext SA attribute
#: in Phase 1, which is why VISION.md section 5.1 marks it Observed for IKEv1
#: and Unknown for IKEv2.
IKEV1_AUTH_METHOD: Final[dict[int, str]] = {
    1: "PRE_SHARED_KEY",
    2: "DSS_SIGNATURES",
    3: "RSA_SIGNATURES",
    4: "ENCRYPTION_WITH_RSA",
    5: "REVISED_ENCRYPTION_WITH_RSA",
    6: "RESERVED_EC_DSS",
    7: "EC_DSS_SHA256",
    8: "EC_DSS_SHA384",
    9: "EC_DSS_SHA512",
    64221: "HYBRID_INIT_RSA",
    64222: "HYBRID_RESP_RSA",
    64223: "HYBRID_INIT_DSS",
    64224: "HYBRID_RESP_DSS",
    65001: "XAUTH_INIT_PRE_SHARED",
    65002: "XAUTH_RESP_PRE_SHARED",
    65003: "XAUTH_INIT_DSS",
    65004: "XAUTH_RESP_DSS",
    65005: "XAUTH_INIT_RSA",
    65006: "XAUTH_RESP_RSA",
    65007: "XAUTH_INIT_RSA_ENCRYPTION",
    65008: "XAUTH_RESP_RSA_ENCRYPTION",
    65009: "XAUTH_INIT_RSA_REVISED_ENCRYPTION",
    65010: "XAUTH_RESP_RSA_REVISED_ENCRYPTION",
}

#: Life types for IKEV1_ATTR_LIFE_TYPE.
IKEV1_LIFE_TYPE: Final[dict[int, str]] = {1: "SECONDS", 2: "KILOBYTES"}

#: Authentication methods that rest on a pre-shared key, so are exposed to an
#: offline dictionary attack when Aggressive Mode puts the identity and the hash
#: on the wire. Read by rule IKE-002.
IKEV1_PSK_AUTH_METHODS: Final[frozenset[int]] = frozenset({1, 65001, 65002})

# ------------------------------------------------- structural algorithm facts

#: Cipher block size in bytes. A 64-bit block cipher is what rule ESP-010 looks
#: for in the ESP length residues, so these numbers feed the inference as well
#: as the report. IKEv1 names are included because the two registries differ.
BLOCK_SIZE_BYTES: Final[dict[str, int]] = {
    "ENCR_DES": 8,
    "ENCR_DES_IV32": 8,
    "ENCR_DES_IV64": 8,
    "ENCR_3DES": 8,
    "ENCR_IDEA": 8,
    "ENCR_3IDEA": 8,
    "ENCR_BLOWFISH": 8,
    "ENCR_CAST": 8,
    "ENCR_RC5": 8,
    "ENCR_AES_CBC": 16,
    "ENCR_CAMELLIA_CBC": 16,
    "DES_CBC": 8,
    "3DES_CBC": 8,
    "IDEA_CBC": 8,
    "BLOWFISH_CBC": 8,
    "CAST_CBC": 8,
    "AES_CBC": 16,
    "CAMELLIA_CBC": 16,
}

#: AEAD transforms carry their own integrity check, so an SA using one is not
#: unprotected even with no separate INTEG transform. Rule ESP-001 depends on
#: this distinction to avoid a false positive on AES-GCM.
AEAD_ENCR: Final[frozenset[str]] = frozenset(
    {
        "ENCR_AES_CCM_8",
        "ENCR_AES_CCM_12",
        "ENCR_AES_CCM_16",
        "ENCR_AES_GCM_8",
        "ENCR_AES_GCM_12",
        "ENCR_AES_GCM_16",
        "ENCR_AES_CCM_8_IIV",
        "ENCR_AES_GCM_16_IIV",
        "ENCR_NULL_AUTH_AES_GMAC",
        "ENCR_CAMELLIA_CCM_8",
        "ENCR_CAMELLIA_CCM_12",
        "ENCR_CAMELLIA_CCM_16",
        "ENCR_CHACHA20_POLY1305",
        "ENCR_CHACHA20_POLY1305_IIV",
        "ENCR_KUZNYECHIK_MGM_KTREE",
        "ENCR_MAGMA_MGM_KTREE",
        "ENCR_KUZNYECHIK_MGM_MAC_KTREE",
        "ENCR_MAGMA_MGM_MAC_KTREE",
    }
)

#: Counter-mode transforms are stream-like, so ESP payloads under them are not
#: padded to a block boundary. The inference engine uses this: a counter or AEAD
#: mode spreads ESP lengths across all four residues modulo 4, whereas CBC pins
#: them to one residue for a 16-byte block and two for an 8-byte block.
COUNTER_MODE_ENCR: Final[frozenset[str]] = frozenset(
    {"ENCR_AES_CTR", "ENCR_CAMELLIA_CTR", "ENCR_CHACHA20_POLY1305"}
)

#: Transforms that provide no confidentiality at all. Named explicitly so a NULL
#: cipher is reported as such rather than mistaken for an unrecognised algorithm.
NULL_ENCR: Final[frozenset[str]] = frozenset({"ENCR_NULL", "ENCR_NULL_AUTH_AES_GMAC"})

#: Integrity check value length in bytes, by algorithm name. This is read off
#: the wire as an ESP trailer length, so it is one of the few child SA facts that
#: can be narrowed without decryption. AEAD ciphers appear here too, since their
#: tag occupies the same position.
ICV_BYTES: Final[dict[str, int]] = {
    "AUTH_HMAC_MD5_96": 12,
    "AUTH_HMAC_SHA1_96": 12,
    "AUTH_AES_XCBC_96": 12,
    "AUTH_AES_CMAC_96": 12,
    "AUTH_HMAC_MD5_128": 16,
    "AUTH_HMAC_SHA1_160": 20,
    "AUTH_HMAC_SHA2_256_128": 16,
    "AUTH_HMAC_SHA2_384_192": 24,
    "AUTH_HMAC_SHA2_512_256": 32,
    "AUTH_AES_128_GMAC": 16,
    "AUTH_AES_192_GMAC": 16,
    "AUTH_AES_256_GMAC": 16,
    "ENCR_AES_GCM_8": 8,
    "ENCR_AES_GCM_12": 12,
    "ENCR_AES_GCM_16": 16,
    "ENCR_AES_CCM_8": 8,
    "ENCR_AES_CCM_12": 12,
    "ENCR_AES_CCM_16": 16,
    "ENCR_CHACHA20_POLY1305": 16,
}

#: Reverse of ICV_BYTES, for turning an observed trailer length back into the
#: set of algorithms that could have produced it. The result is a candidate set,
#: never a single answer, which is why the ESP analyzer reports a cipher family
#: rather than an algorithm.
ICV_CANDIDATES: Final[dict[int, tuple[str, ...]]] = {
    8: ("ENCR_AES_GCM_8", "ENCR_AES_CCM_8"),
    12: (
        "AUTH_HMAC_MD5_96",
        "AUTH_HMAC_SHA1_96",
        "AUTH_AES_XCBC_96",
        "AUTH_AES_CMAC_96",
        "ENCR_AES_GCM_12",
        "ENCR_AES_CCM_12",
    ),
    16: (
        "AUTH_HMAC_MD5_128",
        "AUTH_HMAC_SHA2_256_128",
        "AUTH_AES_128_GMAC",
        "AUTH_AES_192_GMAC",
        "AUTH_AES_256_GMAC",
        "ENCR_AES_GCM_16",
        "ENCR_AES_CCM_16",
        "ENCR_CHACHA20_POLY1305",
    ),
    20: ("AUTH_HMAC_SHA1_160",),
    24: ("AUTH_HMAC_SHA2_384_192",),
    32: ("AUTH_HMAC_SHA2_512_256",),
}

# ------------------------------------------------------------------- lookups


def _name(registry: dict[int, str], value: int, prefix: str) -> str:
    """Look up a numeric ID, falling back to a readable placeholder.

    Never returns None. An ID the parser does not know still has to reach the
    report, because silently dropping it would hide exactly the unusual
    configuration an analyst most wants to see.
    """
    return registry.get(value, f"{prefix}_UNKNOWN_{value}")


def encr_name(value: int) -> str:
    return _name(ENCR, value, "ENCR")


def prf_name(value: int) -> str:
    return _name(PRF, value, "PRF")


def integ_name(value: int) -> str:
    return _name(INTEG, value, "AUTH")


def dh_group_name(value: int) -> str:
    return _name(DH_GROUPS, value, "DH")


def esn_name(value: int) -> str:
    return _name(ESN, value, "ESN")


def notify_name(value: int) -> str:
    return _name(NOTIFY_TYPES, value, "NOTIFY")


def exchange_name_v2(value: int) -> str:
    return _name(EXCHANGE_TYPES_V2, value, "EXCHANGE")


def exchange_name_v1(value: int) -> str:
    return _name(EXCHANGE_TYPES_V1, value, "EXCHANGE")


def payload_name_v2(value: int) -> str:
    return _name(PAYLOAD_TYPES_V2, value, "PAYLOAD")


def protocol_name(value: int) -> str:
    return _name(PROTOCOL_IDS, value, "PROTO")


def ikev1_encr_name(value: int) -> str:
    return _name(IKEV1_ENCR, value, "IKEV1_ENCR")


def ikev1_hash_name(value: int) -> str:
    return _name(IKEV1_HASH, value, "IKEV1_HASH")


def ikev1_auth_name(value: int) -> str:
    return _name(IKEV1_AUTH_METHOD, value, "IKEV1_AUTH")


def transform_name(transform_type: int, transform_id: int) -> str:
    """Name a transform given its type and ID, for a generic transform walker."""
    table = {
        TRANSFORM_ENCR: encr_name,
        TRANSFORM_PRF: prf_name,
        TRANSFORM_INTEG: integ_name,
        TRANSFORM_DH: dh_group_name,
        TRANSFORM_ESN: esn_name,
    }.get(transform_type)
    if table is None:
        return f"TYPE{transform_type}_ID{transform_id}"
    return table(transform_id)


def is_aead(encr: str | None) -> bool:
    """Whether an encryption transform provides its own integrity protection."""
    return encr in AEAD_ENCR if encr else False


def is_null_cipher(encr: str | None) -> bool:
    return encr in NULL_ENCR if encr else False


def block_size(encr: str | None) -> int | None:
    """Block size in bytes, or None for stream, counter and AEAD modes."""
    return BLOCK_SIZE_BYTES.get(encr) if encr else None


def dh_strength_bits(group: int | None) -> int | None:
    """Approximate classical security strength of a key exchange group."""
    return DH_GROUP_STRENGTH_BITS.get(group) if group is not None else None


def is_post_quantum_group(group: int | None) -> bool:
    return group in PQ_DH_GROUPS if group is not None else False


def icv_candidates(icv_bytes: int) -> tuple[str, ...]:
    """Algorithms consistent with an observed ICV length.

    Returns an empty tuple for a length no known algorithm produces, which is
    itself worth reporting rather than rounding to the nearest guess.
    """
    return ICV_CANDIDATES.get(icv_bytes, ())
