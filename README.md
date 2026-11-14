# K9o.Kibo

Official .NET SDK for [Kilimanjaro](#75-about-kilimanjaro) Kibo.

Encrypt and decrypt on the client with keys held in your own KMS, so the platform never sees plaintext.

The platform never sees plaintext or unwrapped keys. Encryption and decryption run on your machine, with your KMS credentials.

## Contents

**A. Get started**

1. [Links](#1-links)
2. [Install](#2-install)
3. [Choose the right package](#3-choose-the-right-package)
4. [Usage](#4-usage)

**B. Use Kibo**

5. [Encrypt through client.Crypto on a BYOK or HYOK project](#5-encrypt-through-clientcrypto-on-a-byok-or-hyok-project)

**C. Troubleshoot**

6. [Handling errors](#6-handling-errors)

**D. Reference**

7. [Appendix](#7-appendix)
   - 7.1 [Requirements](#71-requirements)
   - 7.2 [Error codes](#72-error-codes)
   - 7.3 [Methods](#73-methods)
   - 7.4 [Related packages](#74-related-packages)
   - 7.5 [About Kilimanjaro](#75-about-kilimanjaro)
8. [License](#8-license)

## A. Get started

### 1. Links

- Website: <https://kilimanjaro.dev>
- Documentation / Developer Hub: <https://docs.kilimanjaro.dev>
- Open source
  - Platform: <https://github.com/k9o-platform>
  - Community: <https://github.com/k9o-community>

### 2. Install

```bash
dotnet add package K9o.Kibo --version 1.5.2
```

Requires .NET 8 or newer and a native library for your platform. See [requirements](#71-requirements).

### 3. Choose the right package

| Package | Use it when you are… | Registry | Source |
| --- | --- | --- | --- |
| `K9o.Core` | Building a backend service: the platform client and Gate. | [NuGet](https://www.nuget.org/packages/K9o.Core) | [sdk-dotnet](https://github.com/k9o-platform/sdk-dotnet) |
| `K9o.Kibo` | Encrypting and decrypting with a key you hold in your own KMS. | [NuGet](https://www.nuget.org/packages/K9o.Kibo) | [sdk-kibo-dotnet](https://github.com/k9o-platform/sdk-kibo-dotnet) |

### 4. Usage

`K9o.Kibo.Kibo` has two static, synchronous methods: `Encrypt` and `Decrypt`. See [methods](#73-methods) for details.

The example below encrypts a short text and decrypts it again.

```csharp
using System.Text;
using K9o;
using K9o.Kibo;
using uniffi.kibo_kms_rest_ffi;

var context = new List<FfiKvPair> { new FfiKvPair("tenant", "acme") };
var expiresAt = (ulong)DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds();
var credential = new FfiCredential("<kms-session-token>", expiresAt);
var provider = new FfiProviderConfig("us-east-1", null);
var keyRef = new FfiKeyRef(1, "arn:aws:kms:us-east-1:111122223333:key/<key-id>");

var encryptInput = new EncryptInput(
    KmsProvider.AwsKms, FfiPosture.Byok, null, null,
    credential, keyRef, provider, FfiAttestationTier.Software,
    context, Encoding.UTF8.GetBytes("Write docs"), null,
    new List<string> { "arn:aws:kms:us-east-1:111122223333:key/<key-id>" });

EncryptOutput encrypted = Kibo.Encrypt(encryptInput);

var decryptInput = new DecryptInput(
    credential, provider, encrypted.envelope,
    FfiStrategy.LocalEnvelope, FfiAttestationTier.Software, context,
    new List<string> { "arn:aws:kms:us-east-1:111122223333:key/<key-id>" });
DecryptOutput decrypted = Kibo.Decrypt(decryptInput);

Console.WriteLine(Encoding.UTF8.GetString(decrypted.plaintext));
```

```text
Write docs
```

- The input and output types live in the namespace `uniffi.kibo_kms_rest_ffi`.
- When decrypting, supply the same strategy, attestation tier and encryption context used to encrypt.
- Decryption fails if any of those three differ.

[↑ Back to Contents](#contents)

## B. Use Kibo

### 5. Encrypt through client.Crypto on a BYOK or HYOK project

The platform never sees the plaintext or the key. The key, your cloud and the exchange are all set here, from your own configuration.

Setup:

1. Install the package: `dotnet add package K9o.Kibo`.
2. Get the native library for your platform from the Kibo core bundle (`zk-bundle-v2.16.3` or later) and put it where the package expects it: `runtimes/<rid>/native/` in your application's output (for example `runtimes/osx-arm64/native/libkibo_kms_rest_ffi.dylib`, `runtimes/linux-x64/native/libkibo_kms_rest_ffi.so`, `runtimes/win-x64/native/kibo_kms_rest_ffi.dll`), or next to your application's executable.
3. Create `FfiAppCore` and pass it to `KiboClientCore`. `FfiAppCore` only passes your data to the native library and returns its answers; the cryptography runs in the library. The library is loaded on the first call.

```csharp
using K9o;
using K9o.Kibo.ClientCore;

var key = "arn:aws:kms:eu-central-1:111122223333:key/abc";

client.Crypto.UseClientCore(new KiboClientCore(new KiboClientCoreConfig
{
    Provider = KeyRefProvider.Aws,
    Posture = PostureKind.Byok,
    KeyRef = new FfiKeyRef(1, key),
    ProviderConfig = new FfiProviderConfig("eu-central-1", null),
    Federation = new FfiFederationSpec.Aws(roleArn, "app", "eu-central-1", key, 900),
    ExpectedKeyRefs = new[] { key }, // required
    FederatedToken = async (crypt, op, ct) => (await client.Crypto.FederatedTokenAsync(crypt, op, ct)).Data!,
    Core = new FfiAppCore(),
}));
```

- `ExpectedKeyRefs` is required. Without it the core would open whatever key a stored container names.
- A federated-token response that names another `Provider` or `ProjectId` is refused, never followed.
- The exchange is abandoned after `ExchangeDeadline` (30 s) with `KIBO_EXCHANGE_TIMEOUT`.
- A core that lacks the app-crypto functions is refused with `KIBO_WASM_ERROR`; use `zk-bundle-v2.16.3` or later. One that does not list `expected_key_refs` is refused with `K9O_CRYPTO_KEY_PIN_UNENFORCED`.
- A failure of the exchange is thrown as `KError`. A failure on one item (for example `UPSTREAM_KMS_ERROR` from your own KMS) is reported on that item; the others still succeed.
- `FfiAppCore.Describe(error)` renders an error as `<CODE>: <detail>`.

[↑ Back to Contents](#contents)

## C. Troubleshoot

### 6. Handling errors

Failures are thrown as `K9o.KError` from `K9o.Core`. Codes from the cryptographic core pass through unchanged.

```csharp
try
{
    Kibo.Encrypt(encryptInput);
}
catch (KError e)
{
    Console.WriteLine(e.Code);
}
```

See [error codes](#72-error-codes) for what each situation returns.

[↑ Back to Contents](#contents)

## D. Reference

### 7. Appendix

- [Requirements](#71-requirements)
- [Error codes](#72-error-codes)
- [Methods](#73-methods)
- [Related packages](#74-related-packages)
- [About Kilimanjaro](#75-about-kilimanjaro)

#### 7.1 Requirements

| Requirement | Detail |
|---|---|
| .NET | 8 or newer |
| Native library | From the Kibo core bundle (`zk-bundle-v2.16.3` or later), under `runtimes/<rid>/native/` or next to the executable; loaded on the first call |
| Dependencies | `K9o.Core`, which provides `KError` |

#### 7.2 Error codes

| Situation | `Code` |
|---|---|
| Your declared posture floor rejects the request | `K9O_CRYPTO_POSTURE_FLOOR_VIOLATION` |
| Another platform error from the core | The code the core returned |
| Your KMS returned an error | `UPSTREAM_KMS_ERROR` |
| Any other failure in the core | `KIBO_FFI_ERROR` |
| The client core's exchange ran past its deadline | `KIBO_EXCHANGE_TIMEOUT` |
| The client core's native core lacks the app-crypto functions | `KIBO_WASM_ERROR` |

A posture-floor error also sets `Context` entries `dimension`, `requested` and `declared`.

#### 7.3 Methods

| Method | What it does |
|---|---|
| `EncryptOutput Encrypt(EncryptInput input)` | Encrypts plaintext through your KMS and returns an opaque envelope |
| `DecryptOutput Decrypt(DecryptInput input)` | Decrypts an envelope produced by `Encrypt` |

#### 7.4 Related packages

| Package | Purpose |
|---|---|
| `K9o.Core` | The Kilimanjaro platform client |

#### 7.5 About Kilimanjaro

Kilimanjaro is a modular developer platform for building secure enterprise applications.
You define AI agents, functions and data pipelines on the platform.
The SDKs let you deploy and invoke them, read and write your data, publish to and subscribe to streams, sign users in,
and encrypt with keys you hold.

It provides four building blocks:

- **Keep**: AI security and governance. Guardrails and policy for the agents you run.
- **Pulse**: data intelligence and real-time stream processing. Streams, analytics and live feeds.
- **Gate**: customer identity and access management. Sign-in and sessions, and automatic data scoping
  so a signed-in user reaches only their own data.
- **Kibo**: cryptographic keys and secrets management. Client-side encryption with keys you hold, and a secrets vault.

### 8. License

Apache-2.0 © Formelo Inc. See `LICENSE` and `NOTICE`.

[↑ Back to Contents](#contents)
