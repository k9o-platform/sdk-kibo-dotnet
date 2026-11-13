using System.Collections.Generic;

using uniffi.kibo_kms_rest_ffi;

namespace K9o.Kibo;

/// <summary>
/// Zero-Knowledge BYOK/HYOK vault crypto for .NET — <c>Kibo.Encrypt</c> /
/// <c>Kibo.Decrypt</c> run entirely client-side against your own KMS. The
/// platform never sees plaintext or unwrapped keys.
/// </summary>
/// <remarks>
/// ZERO crypto here: every wrap/unwrap, envelope framing, posture-floor
/// enforcement, and KMS round-trip lives in the audited Rust core
/// (<c>kibo-kms-rest-ffi</c>, piece C). .NET's P/Invoke calling convention is
/// synchronous, so this calls the core's <c>ZkEncryptBlocking</c> /
/// <c>ZkDecryptBlocking</c> exports (crypto-identical to the async exports the
/// mobile SDKs use). The three <c>ZkFfiUniffiException</c> variants map to the
/// shared <see cref="K9o.KError"/> (consistent with the Python/Ruby/Java server
/// SDKs); codes are passed through from the core, never hardcoded.
/// </remarks>
public static class Kibo
{
    /// <summary>
    /// Encrypt <c>input.plaintext</c> via the customer KMS, client-side.
    /// Returns the opaque ZKFE envelope. Throws <see cref="K9o.KError"/> on failure.
    /// </summary>
    public static EncryptOutput Encrypt(EncryptInput input)
    {
        try
        {
            return KiboKmsRestFfiMethods.ZkEncryptBlocking(input);
        }
        catch (ZkFfiUniffiException e)
        {
            throw ToKError(e);
        }
    }

    /// <summary>
    /// Decrypt a ZKFE <c>input.envelope</c>. <c>strategy</c>,
    /// <c>attestationTier</c>, and <c>encryptionContext</c> MUST match the
    /// encrypt-time values (AAD-bound). Throws <see cref="K9o.KError"/> on failure.
    /// </summary>
    public static DecryptOutput Decrypt(DecryptInput input)
    {
        try
        {
            return KiboKmsRestFfiMethods.ZkDecryptBlocking(input);
        }
        catch (ZkFfiUniffiException e)
        {
            throw ToKError(e);
        }
    }

    private static KError ToKError(ZkFfiUniffiException e) => e switch
    {
        ZkFfiUniffiException.PostureViolation pv => new KError(
            pv.code,
            pv.detail,
            new Dictionary<string, object?>
            {
                ["dimension"] = pv.dimension,
                ["requested"] = pv.requested,
                ["declared"] = pv.declared,
            },
            null, null, null),
        ZkFfiUniffiException.Platform pl => new KError(pl.code, pl.detail),
        // Customer's own KMS failed — no K9O_* code (upstream failures carry no K9O_* code).
        ZkFfiUniffiException.UpstreamKms uk => new KError("UPSTREAM_KMS_ERROR", uk.detail),
        _ => new KError("KIBO_FFI_ERROR", e.Message),
    };
}
