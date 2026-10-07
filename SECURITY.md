# Security Policy

- **Repository:** <https://github.com/saloni-29-01/AI-Based-Network-IDS_ML-DL>
- **Maintainer:** [Saloni Kumari](https://github.com/saloni-29-01)

## Scope

This is an academic intrusion-detection project (B.Tech final-year project)
trained on the public NSL-KDD benchmark dataset. It is **not** a production
security product:

- the models reflect 1998-era benchmark traffic, so verdicts on live traffic
  are indicative only;
- the API and dashboard have **no authentication** and are meant to run on
  `127.0.0.1` (do not expose them on an untrusted network);
- it has not been hardened against adversarial or evasive input.

Do not rely on it as your only network defence.

## Reporting a vulnerability

If you find a security issue in this repository (for example unsafe
deserialisation of model files, a dependency with a known CVE, an API
endpoint that can be abused, or a way to make the application execute
arbitrary code):

1. **Do not** open a public GitHub issue.
2. Report it privately via GitHub:
   [Security → Report a vulnerability](https://github.com/saloni-29-01/AI-Based-Network-IDS_ML-DL/security/advisories/new).
   Include a description, the affected file or endpoint, and steps to reproduce.
3. You should receive an acknowledgement within a few days.

Please give reasonable time for a fix before any public disclosure.

## Safe use

- Load model files (`models/**/*.joblib`, `*.keras`) only from this repository
  or from your own training runs; pickled files can execute code when loaded.
- Keep `APP_HOST=127.0.0.1` unless you are on a trusted network.
- Never commit a real `ALERT_WEBHOOK_URL` or other secrets; use `.env`, which
  is git-ignored.

## Supported versions

Only the latest commit on the default branch is supported.
