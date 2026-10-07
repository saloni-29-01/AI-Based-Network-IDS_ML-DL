# Contributing

Thanks for considering a contribution to this project! It began as a fork
of [mohammedAcheddad/AI-Based-Network-IDS_ML-DL](https://github.com/mohammedAcheddad/AI-Based-Network-IDS_ML-DL)
(see [README.md](README.md) for full credit) and has since been modernized
and extended.

## Ways to contribute

- **Bug reports** -- open an issue using the Bug Report template.
- **Feature ideas** -- open an issue using the Feature Request template.
- **Pull requests** -- for anything beyond a small fix, please open an
  issue first to discuss the change.

## Development setup

```bash
git clone <YOUR_REPOSITORY_URL_HERE>
cd AI-Based-Network-IDS_ML-DL
python -m venv .venv
source .venv/bin/activate  # on Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
```

## Before opening a pull request

- Run `ruff check .` and `black --check .`.
- Make sure both notebooks still execute top-to-bottom without errors.
- Update `CHANGELOG.md` with a short summary of your change.
- Keep pull requests focused -- one topic per PR is easier to review.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
