# Self-hosted RustDesk service

This directory adds an open-source account and address-book API compatible with
the Flutter client in this fork. It is designed for the A100 host at
`223.105.144.22`, where every externally reachable service must use a port above
10000.

## Endpoints

- RustDesk ID server: `223.105.144.22:21116` (TCP and UDP)
- RustDesk relay server: `223.105.144.22:21117` (TCP)
- Account and address-book API: `https://223.105.144.22:21114`
- RustDesk auxiliary and WebSocket ports: `21115`, `21118`, and `21119`

The API provides registration, login, personal address books, a global
`Shared devices` address book, aliases, notes, tags, and shared passwords. All
authenticated users have full control of the global address book. Shared
passwords are encrypted with AES-256-GCM in SQLite and are returned only to an
authenticated client.

Desktop clients ask for a local device alias during installation or sign-in.
After authentication, `POST /api/device/upsert` automatically creates or
updates that RustDesk ID in the global address book. Renaming the local alias
and signing in again updates the name without replacing an existing shared
password.

The public private-CA certificate is bundled at
`flutter/assets/self_hosted_ca.pem`. The CA private key and server private key
must remain only on the server.

## Account server configuration

Build the standalone crate in `account-server`, install the binary at
`/opt/rustdesk-selfhost/account/rustdesk-account-server`, and copy
`deploy/account.env.example` to
`/opt/rustdesk-selfhost/account/account.env`. Generate the encryption key with:

```bash
openssl rand -base64 32
```

Set file mode `0600` on `account.env`; it contains the database encryption key.
The systemd units in `deploy/` assume the service account is named
`rustdesk-selfhost`.

## Security boundary

The global address book intentionally exposes each shared device password to
every authenticated account. Do not register untrusted users. Disable new
registrations after onboarding by setting
`RUSTDESK_ACCOUNT_ALLOW_REGISTRATION=false` and restarting the account service.
