# Changelog

## [0.4.6] - 2026-11-07

### Changed

- Update wecanencrypt to 0.17.0, pgp to 0.21, and dirs to 7.
- Refresh compatible dependencies in Cargo.lock.

### Security

- Temporarily except RUSTSEC-2026-0387 from the dependency audit while
  upstream dependencies require crypto-bigint 0.5. The vulnerability remains
  unresolved; remove the exception when a compatible fix becomes available.
- Run the security audit when its configuration changes.
