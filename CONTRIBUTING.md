# Contributing

Thank you for improving `multipath-delay-measurements`. This repository is kept public for reproducible research and engineering reuse, so changes should stay small, documented, and easy to verify.

## Scope

- Keep each change focused on one purpose.
- Do not commit generated artifacts, local logs, private paths, credentials, datasets, model weights, or machine-specific configuration.
- Put reusable scripts under `scripts/` when the repository already uses that layout.
- Update `README.md` when commands, expected outputs, datasets, or external dependencies change.

## Local Checks

Before pushing a change, run the checks that match the files you changed:

```bash
git diff --check
python3 -m compileall .
```

If a check requires data, containers, or hardware that is not publicly available, document the smallest public smoke test in `README.md`.

## Issues and Pull Requests

When reporting an issue or proposing a change, include:

- the command you ran;
- the expected result;
- the observed result;
- the commit or release you used;
- the relevant environment details.
