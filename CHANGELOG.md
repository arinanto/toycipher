# CHANGELOG

<!-- version list -->

## v1.0.0-rc.1 (2026-11-18)

### Build System

- **release**: Bump breaking changes on 0.x to 1.0.0
  ([#1](https://github.com/arinanto/toycipher/pull/1),
  [`3af29cf`](https://github.com/arinanto/toycipher/commit/3af29cfe2a7b1d80a79d93d784810416c120dccd))

### Chores

- **lock**: Sync uv.lock with 0.1.0-rc.5 ([#1](https://github.com/arinanto/toycipher/pull/1),
  [`3af29cf`](https://github.com/arinanto/toycipher/commit/3af29cfe2a7b1d80a79d93d784810416c120dccd))

### Continuous Integration

- **test**: Run pytest as a PR status check ([#1](https://github.com/arinanto/toycipher/pull/1),
  [`3af29cf`](https://github.com/arinanto/toycipher/commit/3af29cfe2a7b1d80a79d93d784810416c120dccd))

### Documentation

- **readme**: Document the v2 KMAC256 key expansion
  ([#1](https://github.com/arinanto/toycipher/pull/1),
  [`3af29cf`](https://github.com/arinanto/toycipher/commit/3af29cfe2a7b1d80a79d93d784810416c120dccd))

### Features

- **kdf**: Derive cascade material with KMAC256 and bump the format to v2
  ([#1](https://github.com/arinanto/toycipher/pull/1),
  [`3af29cf`](https://github.com/arinanto/toycipher/commit/3af29cfe2a7b1d80a79d93d784810416c120dccd))

- **kdf**: KMAC256 key expansion and v2 file format
  ([#1](https://github.com/arinanto/toycipher/pull/1),
  [`3af29cf`](https://github.com/arinanto/toycipher/commit/3af29cfe2a7b1d80a79d93d784810416c120dccd))


## v0.1.0-rc.5 (2026-11-18)

### Bug Fixes

- **ci**: Let a manual dispatch force a version level
  ([`995c614`](https://github.com/arinanto/toycipher/commit/995c61414ca7043e85fa1bab6659e2a414f4a3ac))


## v0.1.0-rc.4 (2026-11-18)

### Bug Fixes

- **ci**: Attach release assets with gh instead of semantic-release publish
  ([`afcfa27`](https://github.com/arinanto/toycipher/commit/afcfa2777e91ab9a408d04d4d2b110066ebe5f60))

- **spec**: Find the abi3t stub where Windows 3.15 actually keeps it
  ([`a112b73`](https://github.com/arinanto/toycipher/commit/a112b73da212c1ed012fd28b983569a27187270c))


## v0.1.0-rc.3 (2026-11-18)

### Bug Fixes

- **spec**: Bundle the abi3t stub so the Windows build can import its deps
  ([`2ac306e`](https://github.com/arinanto/toycipher/commit/2ac306e7b81b9d5409937a7362fb3eb6f74824aa))

### Continuous Integration

- **release**: Publish the platforms that pass instead of all or nothing
  ([`4540895`](https://github.com/arinanto/toycipher/commit/4540895f6e9ae0a7775a1090f5961071d93f9304))


## v0.1.0-rc.2 (2026-11-18)

### Bug Fixes

- **ci**: Pin setup-uv to a tag that exists
  ([`264c0bc`](https://github.com/arinanto/toycipher/commit/264c0bc5c30a0708ea5674265862229e4df2abfc))


## v0.1.0-rc.1 (2026-11-18)

- Initial Release
