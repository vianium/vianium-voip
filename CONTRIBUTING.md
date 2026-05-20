# Contributing to vianium-voip

Thanks for your interest in contributing. This document explains how to
submit changes, what is expected, and how the project handles attribution
and licensing of your contributions.

## Before you contribute

This repository is part of the [Vianium](https://github.com/vianium) project.
Read the [Vianium contribution guide](https://github.com/vianium/vianium-docs/blob/main/contribution-guide.md)
for cross-repo conventions, then come back here for repo-specific rules.

## Developer Certificate of Origin (DCO)

All contributions require **DCO sign-off**. By signing off, you certify
that you wrote the code or have the right to submit it under the project
license. The DCO is a lightweight alternative to a CLA. There is nothing
to sign physically; just add a `Signed-off-by` line to your commits.

### How to sign off

Use the `-s` flag when committing:

```sh
git commit -s -m "your commit message"
```

This adds a trailer like:

```text
Signed-off-by: Your Name <your.email@example.com>
```

The name and email should match your real identity.

### Full DCO text

See [developercertificate.org](https://developercertificate.org/).

## How to contribute

### Reporting bugs

Open an issue using the **Bug report** template. Include:

- Repro steps.
- Expected vs. actual behavior.
- Environment: OS, toolchain, version.

### Proposing features

Open an issue using the **Feature request** template before writing code.
Large changes need design discussion first.

### Submitting code

1. Fork the repository.
2. Create a topic branch: `git checkout -b feat/short-description`.
3. Make your changes. Follow the style in [.editorconfig](.editorconfig)
   and existing code conventions.
4. Add tests where applicable.
5. Commit with DCO sign-off: `git commit -s`.
6. Push to your fork and open a pull request against `main`.
7. Fill in the PR template completely.

### Pull request requirements

- All commits signed off with DCO.
- CI green.
- One approving review from a maintainer.
- No merge conflicts with `main`.
- License headers preserved at the top of source files.

## Coding style

- **C++**: Prefer C++11/14 while legacy toolchains are supported.
- **C#**: Use language features supported by the target platform.
- **PowerShell**: Scripts should be idempotent and use `SupportsShouldProcess`
  when they modify files.
- **Line endings**: LF for source files, CRLF for `.sln`, `.vcxproj`, and
  related Visual Studio project files.

## License of contributions

By submitting a contribution, you agree it will be licensed under the same
license as this repository. See [LICENSE](LICENSE).

If your contribution includes third-party code, you must:

- Add an entry to `THIRD_PARTY_NOTICES.md`.
- Preserve the upstream license file under `LICENSES/`.
- Confirm license compatibility.

## Communication

- **Issues** for bugs and feature requests.
- **Discussions** for questions and design conversations.
- **Pull requests** for code changes.

Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
