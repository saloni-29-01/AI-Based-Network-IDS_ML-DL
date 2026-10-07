# Security Policy

## Scope

This is a research/educational intrusion-detection project trained on the
public NSL-KDD benchmark dataset. It is **not** a production security
product, is not hardened against adversarial input, and should not be
deployed as a live network defense without significant additional work
(input validation, adversarial robustness testing, monitoring, etc.).

## Reporting a Vulnerability

If you discover a security issue in this repository (e.g. unsafe
deserialization, a dependency with a known CVE, or a way to make the
training/inference scripts execute arbitrary code), please open a private
report:

1. **Do not** open a public GitHub issue for security-sensitive reports.
2. Email `<YOUR_CONTACT_EMAIL_HERE>` with a description of the issue and,
   if possible, steps to reproduce it.
3. You should receive an acknowledgement within a few days.

## Supported Versions

Only the latest commit on the default branch is supported.
