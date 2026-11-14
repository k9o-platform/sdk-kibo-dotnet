# Changelog — K9o.Kibo (.NET)

## 1.5.2

### Changed

- README: Architecture at a glance, illustrations, and the package table lists only the packages for that SDK.

## 1.5.0

### Added

- `K9o.Kibo.ClientCore.KiboClientCore`: the client core for `client.Crypto` on a BYOK or HYOK project. Register it with `client.Crypto.UseClientCore(core)`. It fetches the federated token, exchanges it with your cloud (`acquire_kms_credential`, with a deadline, 30 s by default, `KIBO_EXCHANGE_TIMEOUT` on expiry), then seals or opens with your own KMS. Needs `zk-bundle-v2.16.3` or later.
- `K9o.Kibo.ClientCore.FfiAppCore`: the core to pass as `KiboClientCoreConfig.Core`. It converts your data to and from the generated binding and calls the native library; errors become `KError` (`UPSTREAM_KMS_ERROR` when your own KMS refuses). The native library is found under `runtimes/<rid>/native/` or next to the executable, and is loaded on the first call.
- A key pin is required: it refuses to be built without a non-empty `ExpectedKeyRefs`, refuses a core that does not list `expected_key_refs` (`K9O_CRYPTO_KEY_PIN_UNENFORCED`), and never takes the key, provider or project from the platform's answer. A response naming another provider or project is refused (`K9O_INVALID_FIELD_VALUE`). The exchanged credential is reused until 60 s before it expires; the token is fetched on every call.

### Changed

- The generated binding is the one of `zk-bundle-v2.16.4`. `EncryptInput` and `DecryptInput` take a trailing `ExpectedKeyRefs` list.
- A call whose own `ExpectedKeyRefs` does not contain the configured key is refused per item with `K9O_CRYPTO_UNEXPECTED_KEY` before the federated token is fetched and before the cloud exchange (it was only refused later, inside seal/open).
- README description.
