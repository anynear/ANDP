# Contributing

Thank you for looking at ANDP. Issues and pull requests are welcome, in English or German.

## Rules

- **Specification first.** A change of a format or of behaviour changes `spec/andp.md`, the test vectors and the
  Kotlin client together.
- **Version v1 stays compatible.** Paths `/andp/v1/…`, signing domains `andp/v1/…` and headers `ANDP-…` are never
  renamed. Unknown fields are ignored everywhere; an unknown value rejects only the item that carries it (§13). An
  incompatible change is a new protocol version next to v1.
- **Protocol terms are English** (object, entry, content, space, owner, grant, placement, network list …), as in the
  specification.
- **No home-made cryptography**, and no secrets or personal data in code, tests or vectors. Test keys are derived from
  fixed labels.
- Report vulnerabilities as described in `SECURITY.md`, not in an issue.

## Build and test

See `README.md`. Continuous integration runs the jobs `kotlin` and `ios` on every pull request; both must pass.

## How a pull request gets in

This repository is published from the project's working repository; nobody pushes to `main` here directly. When a pull
request is accepted, the change is applied in the working repository with you as co-author (`Co-authored-by`) and
arrives here with the next update of `main`. The pull request is then closed with a link to that commit.

## Licence and Contributor License Agreement

Contributions need your agreement to the Contributor License Agreement in [CLA.md](CLA.md): you keep the copyright and
give the project a licence that also allows it to license your contribution under other terms. A bot asks for your
agreement in your first pull request; you agree by commenting the sentence it shows. Accepted contributions stay
available under GPL-3.0-or-later, like the rest of the repository. Because of this agreement, the project can also offer the code
under a commercial licence ([COMMERCIAL.md](COMMERCIAL.md)). The name “anynear” and its logos are not covered by any
of these licences.
