# Security Policy

SIGIL/1 is a security component. Treat the KMS keys and the anchor store as roots of trust.

- Do not commit private keys, tokens, or runtime state.
- Use `sigil-rotate` for key rotation and re-anchor after rotation.
- Run the conformance suite after any change to canonicalization, signing, or verification.
- Report vulnerabilities privately to the maintainers; do not open a public issue with exploit details.
