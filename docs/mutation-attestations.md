# Mutation attestations

Every proxy mutation requires two independent credentials:

1. the caller's Grafana bearer token, which establishes identity and Grafana permissions;
2. a short-lived HMAC attestation, which proves the exact mutation came from the approved
   deployment path.

The CLI creates a fresh attestation for every apply or delete. The signed statement binds the
site, organization, folder, group, operation, reviewed artifact-manifest SHA-256, validity window,
and a random nonce. Applies also bind the canonical desired-payload SHA-256. Deletes instead bind
the reviewed live before-state SHA-256 from the prune or rollback plan.

The proxy verifies the signature and every bound field before writing to Grafana. The signed nonce
becomes the audit request ID. Because the intent audit record is created exclusively before the
Grafana request, the same attestation cannot be used twice.

## Configuration

Generate a random key with at least 32 bytes of entropy:

```bash
openssl rand -hex 32
```

Store the same value in two secret stores:

- Azure Pipelines secret variable `ALERT_ATTESTATION_KEY`
- proxy runtime secret `PROXY_ATTESTATION_KEY`

Do not commit the value or include it in container images. The proxy accepts attestations for at
most 900 seconds by default. A smaller or larger upper bound can be configured with
`PROXY_ATTESTATION_MAX_TTL_SECONDS`; the CLI currently issues 600-second attestations.

The HMAC key does not replace Azure environment approval, Grafana authentication, proxy RBAC,
artifact validation, stale-plan checks, post-deployment verification, or immutable receipts. All
of those controls remain mandatory.
