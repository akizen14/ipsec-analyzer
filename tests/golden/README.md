# Golden captures

Small captures checked into git deliberately, as test oracles. They are the
exception to the rule in PLAN.md section 9 that captures stay out of the
repository, and the `.gitignore` allows this directory explicitly.

Each was produced by the testbed, so its configuration is known exactly rather
than guessed at. The expected values in `expected.json` come from what
strongSwan reported when the tunnel came up, not from what the analyzer
produced, so these tests check the analyzer against reality and not against
itself.

| File | Configuration | Produced by |
|---|---|---|
| `ikev2-aes256-sha256-dh14.pcapng` | IKEv2, AES-CBC-256, HMAC-SHA2-256, PRF HMAC-SHA2-256, DH group 14, ESP tunnel mode. Two child rekeys and one IKE SA rekey. Near-constant packet sizes. | `testbed/compose/ikev2-basic.yml` |
| `ikev2-3des-sha1-dh2-downgrade.pcapng` | IKEv2, 3DES, HMAC-SHA1-96, DH group 2. A strong suite was offered and refused, so the responder forced a downgrade and an `INVALID_KE_PAYLOAD` renegotiation happened first. Varied packet sizes. | `testbed/compose/ikev2-weak.yml` |

The second capture carries the varied packet sizes on purpose: without a spread
of plaintext lengths the ESP length-residue inference correctly abstains, so the
first capture exercises the abstention and the second exercises the positive
case. Both behaviours need a test.

## Regenerating

    sh scripts/testbed-bootstrap.sh
    docker compose -f testbed/compose/ikev2-basic.yml up -d
    # load configs, start tcpdump, swanctl --initiate, generate traffic

The orchestrator in PLAN.md phase 1 replaces those manual steps.
