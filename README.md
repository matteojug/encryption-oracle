# Encryption Oracle

## Run dockerized

```bash
docker compose up
```

## Run native

```bash
cargo run
```

## Run unit tests

```bash
cargo test
```

## Run e2e test

Test interacting with the APIs (requires the service to be running, either native or dockerized)
and checking the returned value by decrypting (with a different implementation) the returned payload.

```bash
cd test-e2e

# Install pipenv deps
pipenv install
# then
pipenv run pytest # [--url <custom url>]
```
