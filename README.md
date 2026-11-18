# toycipher

Password-based, streaming file encryption using a **SM4 → Camellia → AES** CBC cascade
with a **KMAC256** authentication tag.

```
$ toycipher encrypt notes.txt        # -> notes.txt.artcrypt
$ toycipher decrypt notes.txt.artcrypt
```

> [!WARNING]
> This is a toy construction, not a vetted one. Stacking three ciphers is a fun exercise
> and it is implemented carefully, but it has no security proof, has never been audited,
> and is *not* a better choice than a standard AEAD. For real secrets use `age`, or
> AES-GCM/ChaCha20-Poly1305 (`libsodium secretstream` for large files). Read
> [Security notes](#security-notes) before trusting this with anything that matters.

## Design

Confidentiality comes from three block ciphers applied in sequence, each with its own key
and IV. Decrypting requires inverting all three in order (AES, then Camellia, then SM4),
so the ciphertext is at least as strong as the weakest layer — the point is that a break
in any single algorithm is not enough on its own.

Integrity is separate: an encrypt-then-MAC KMAC256 tag covers the whole ciphertext.

| Step | What | Parameters |
| --- | --- | --- |
| 1 | Argon2id stretches the password | `t=3`, `m=64 MiB`, `p=4`, 32-byte output |
| 2 | KMAC256 expands it into 128 bytes of material | `k_sm4`, `k_camellia`, `k_aes` (128-bit), `k_mac` (256-bit), `iv_sm4`, `iv_camellia`, `iv_aes` (128-bit), from one 1024-bit expansion with `master_iv` as the message |
| 3 | PKCS#7 pads the plaintext **once** | 128-bit blocks; all three ciphers share the 16-byte block size, so no layer needs its own padding |
| 4 | Then the cascade runs | `SM4-CBC → Camellia-CBC → AES-CBC` |
| 5 | KMAC256 authenticates | `KMAC256(k_mac, 256-bit, custom="ARTCRYPT_V2_CASCADE_AUTH_TAG")` over `salt ‖ master_iv ‖ ciphertext` |

The master key comes from the password and a random 16-byte salt; the per-layer keys and
IVs, plus `k_mac`, come from one KMAC256 expansion keyed by that master key, with a random
16-byte `master_iv` as the message. The expansion is 1024 bits wide, but its strength is
capped at 256 bits by the master key. Both random values are stored in the header, so each
file is independently keyed even with the same password.

Encryption is a single streaming pass over the input. Decryption is two passes over the
ciphertext: first the tag is verified (nothing is written), then the file is re-read and
decrypted. **Plaintext is never written for a file that fails authentication.**

## File format

```
offset  size         field
0       8            magic        89 41 52 54 43 59 50 54  ("\x89ARTCYPT")
8       4            version      big-endian uint32, currently 2
12      8            length       big-endian uint64, bytes after this field
20      16           salt         Argon2id salt
36      16           master_iv    message for the KMAC256 key/IV expansion
52      n * 16       ciphertext   PKCS#7-padded plaintext, SM4-CBC -> Camellia-CBC -> AES-CBC
-32     32           tag          KMAC256 over salt || master_iv || ciphertext
```

`n = floor(len(plaintext) / 16) + 1`, so the ciphertext is always a multiple of 16 and
always at least one block (an empty file encrypts to a single all-`0x10` padding block).
Streaming uses 64 KiB chunks.

`length` covers `salt || master_iv || ciphertext || tag`, i.e. every byte after the field
itself, and is therefore 80 for an empty file and 64 bytes larger than the ciphertext in
general. It is written from the real byte count once the body is complete, so it always
agrees with the file size even though encryption is a single streaming pass.

The three cheapest checks run first, in this order, and each one bails out on its own:
magic, version (only `2` is accepted), then `length` against the actual file size. All of
them happen before Argon2id, before any crypto and before any output file is created, so a
wrong file, a truncated file, a file with extra bytes, or a format from a future version
costs milliseconds instead of 64 MiB and three passes. The salt and `master_iv` are
authenticated by the tag; the version and length are not covered by it, but both are
self-validating — only one version is accepted, and only one length matches a given file
size — so tampering with either is rejected by the cheap checks.

**Breaking changes:** format version 1 added the version and length fields; version 2
replaced HKDF-SHA-512 with a KMAC256 expansion and shrank the Argon2id output from 48 to
32 bytes, so the derived keys and IVs differ. Files written before version 1 have no
version field, so their first four salt bytes are read as a version; version-1 files carry
`1` there. Both are rejected with `Unsupported format version …` rather than a misleading
authentication failure. Decrypt them with an older build and re-encrypt with this one.

## Install

Requires Python 3.15+.

```sh
uv sync                     # or: pip install -e .
uv run toycipher --help
```

For a single-file binary, a [PyInstaller](https://pyinstaller.org) spec is included (21 MB,
no runtime dependencies):

```sh
uv run pyinstaller toycipher.spec
./dist/toycipher --help
```

PyInstaller needs a Python that ships a shared `libpython`. Most `uv`-managed builds do,
but not all — with one that does not, the build stops at
`Python shared library ... was not found`; pin a different interpreter
(`uv python pin`) and re-create the venv. `toycipher.spec` is tracked even though `*.spec`
is in `.gitignore`, because a hand-maintained spec is source, not generated output.

## Releases

Releases are cut by [Python Semantic Release](https://python-semantic-release.readthedocs.io/)
from the commit messages on `main`, driven by [`.github/workflows/release.yml`](.github/workflows/release.yml).
Nothing is published by hand.

Every push to `main` cuts a **prerelease**: the version is derived from the commits since
the last tag and gets an `rc` suffix (`v0.2.0-rc.1`, then `v0.2.0-rc.2`, …). Each release
carries a PyInstaller binary per platform, built in the same run and attached to the
release page:

| Artifact | Runner |
| --- | --- |
| `toycipher-<version>-linux-amd64` | `ubuntu-24.04` |
| `toycipher-<version>-linux-aarch64` | `ubuntu-24.04-arm` |
| `toycipher-<version>-macos-aarch64` | `macos-26` |
| `toycipher-<version>-windows-amd64.exe` | `windows-2025` |

There is no `windows-aarch64` build: `cryptography` publishes no `win_arm64` wheel, so the
dependency cannot be installed on the ARM runner. Add the commented-out matrix entry back
when a wheel ships.

A platform whose build or smoke test fails does not hold up the others: every platform is
built independently and only the ones that pass are attached, so a release can carry a
subset of the table above. The workflow run still goes red, and the job summary lists what
actually made it onto the release page.

To turn the newest prerelease into a final release, run the `release` workflow manually
(*Actions → release → Run workflow*) with `kind: ga`. It finalises `v0.2.0-rc.2` as
`v0.2.0` rather than starting another `rc`, and the GitHub release is marked as a normal
release instead of a prerelease. No merge or branch is involved.

The binaries are unsigned. macOS quarantines a downloaded arm64 executable, so the first
run needs `xattr -d com.apple.quarantine toycipher`.

## Usage

The operation is an explicit subcommand. It is never inferred from the filename — a file
called `something.artcrypt` is just a file, and anything can be decrypted.

```
toycipher encrypt INPUT [-o OUTPUT] [-p PASSWORD]
toycipher decrypt INPUT [-o OUTPUT] [-p PASSWORD]
```

| Situation | Behaviour |
| --- | --- |
| No mode given | exits `2` (argparse), no file is touched |
| `encrypt`, no `-o` | writes `<name>.artcrypt` in the current directory |
| `decrypt`, no `-o`, name ends in `.artcrypt` | writes `<name>` in the current directory |
| `decrypt`, no `-o`, any other name | writes `<name>.dec` in the current directory |
| `-o` equals the input path | exits `1` before doing any work |
| Wrong password or tampered file | exits `1`, no output file is left behind |
| Ctrl-C | exits `130`, partial output file is removed |

### Passwords

Three sources, in priority order:

1. `-p/--password` — convenient for scripts, but **argv is visible to other processes**
   (`ps`), so prefer the environment variable.
2. `ARTCRYPT_PASSWORD` — not visible in the process list, but readable by anyone who can
   read `/proc/<pid>/environ` as the same user.
3. Interactive prompt (masked), asked twice on encrypt and compared.

An empty password is rejected when encrypting.

```sh
ARTCRYPT_PASSWORD='correct horse' toycipher encrypt backup.tar
ARTCRYPT_PASSWORD='correct horse' toycipher decrypt backup.tar.artcrypt -o backup.tar
```

## Development

```sh
uv run ruff check .        # lint
uv run ruff format .       # format
uv run pyrefly check       # type check (strict)
uv run pytest              # test suite
```

The suite is deterministic: every input is a transparent sequence (`bytes(range(16))`,
`"0123..."`) and every expected value is a hard-coded constant, so a failure means the
format or the derivation changed rather than that the machine got unlucky.
`tests/test_artcrypt.py` pins the Argon2id master key, all seven KMAC256-derived values,
and two complete encrypted files (a 32-byte plaintext and the empty plaintext) in both
directions.
`tests/test_cli.py` covers the subcommand behaviour and the file-naming rules. Expect
~20 seconds — the Argon2id parameters are deliberately not weakened for tests.

## Security notes

What is done deliberately:

- **Encrypt-then-MAC**, verified before any decryption output is written.
- The tag covers the salt and `master_iv`, not just the ciphertext, so header tampering
  is detected too.
- **Domain separation.** The key expansion and the tag use distinct KMAC256 `custom`
  strings, so the two uses cannot be confused with each other.
- Fresh salt and `master_iv` per encryption, so identical plaintexts never collide.
- PKCS#7 is applied exactly once, before the first layer. Intermediate padding would leak
  length structure and grow the file at every layer.
- The magic, the version, the length and the block alignment are all checked before
  Argon2id runs, in that order and each failing on its own, so junk input costs
  milliseconds, not 64 MiB and three passes.

What you should know:

- **Fixed IVs per layer.** Each layer uses a per-file IV derived from a random
  `master_iv`. That is safe for a whole-file, once-per-key use, but the cascade is
  deterministic given (password, salt, IV) — hence the whole-file MAC and the fresh
  randomness on every run.
- **Metadata leaks.** File name, size (rounded up to a multiple of 16), mtime and the
  fact that a file is an artcrypt file are all visible. This is file-level encryption,
  not a vault.
- **Whole-file tag, no chunk AEAD.** Seeking to an offset and decrypting part of a file is
  not supported, and a file must be read twice to decrypt.
- **Password-only.** No key files, no public keys, no multi-recipient support.
- **The padding is unauthenticated on its own** (KMAC covers ciphertext, not plaintext).
  A damaged ciphertext cannot reach the unpadder because the tag is verified first; an
  invalid pad after a valid tag would indicate a bug, not an attack.

## Contributing

Two rules apply to every commit in this repository, the maintainer's own included. They are
kept deliberately even though this is a hobby project.

### 1. Conventional Commits (required)

Every commit message must parse as a [Conventional Commit 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

Use one of `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`,
`chore`, `revert`. Mark a breaking change with `!` after the type/scope (`feat(api)!: ...`)
and a `BREAKING CHANGE:` footer. A commit that does not conform is rejected and has to be
reworded — it will not be massaged into shape during review.

```
fix(cli): reject a missing mode before opening any file
feat(cascade)!: pad the plaintext once instead of per layer
```

### 2. DCO sign-off (required)

Every commit must carry a `Signed-off-by` trailer. Git adds it for you with `-s`:

```sh
git commit -s          # or --signoff
```

Turn it on permanently so it cannot be forgotten:

```sh
git config --local format.signoff true
```

Existing commits can be signed retroactively with `git rebase --signoff <base>`. The
trailer certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you wrote the contribution, or have the right to submit it, under this project's
license. There is no CLA and no copyright assignment — the sign-off is the whole
agreement.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
