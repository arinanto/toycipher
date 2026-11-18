# AGENTS.md

Instructions for AI coding agents and for anyone contributing to this repository.
Project documentation, usage and design notes live in [README.md](README.md).

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
