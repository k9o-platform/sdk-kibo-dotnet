using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using K9o;
using Ffi = uniffi.kibo_kms_rest_ffi;

namespace K9o.Kibo.ClientCore;

/// <summary>
/// The core for <see cref="KiboClientCore"/>: it passes your data to the Kibo core (the native library, <c>kibo_kms_rest_ffi</c>) and returns
/// what it answers. It does no cryptography itself. The native library is loaded on the first call, not when this class is created, so
/// the package loads without it.
/// </summary>
/// <remarks>
/// Failures of the core are thrown as <see cref="KError"/>: a platform error keeps the core's code, your own KMS refusing is
/// <c>UPSTREAM_KMS_ERROR</c>. <see cref="Describe"/> renders one as <c>"&lt;CODE&gt;: &lt;detail&gt;"</c>.
/// </remarks>
public sealed class FfiAppCore : IAppCore
{
    /// <inheritdoc />
    public async Task<byte[]> AppCryptoSealAsync(AppSealInput input, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        var native = new Ffi.AppSealInput(
            Provider(input.Provider), Posture(input.Posture), Cred(input.KmsCred), Key(input.KeyRef), Config(input.ProviderConfig),
            input.ProjectId, input.Crypt, input.Context, input.Plaintext, new List<string>(input.ExpectedKeyRefs));
        var output = await Run(() => Ffi.KiboKmsRestFfiMethods.AppCryptoSeal(native), ct).ConfigureAwait(false);
        return output.container;
    }

    /// <inheritdoc />
    public async Task<byte[]> AppCryptoOpenAsync(AppOpenInput input, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        var native = new Ffi.AppOpenInput(
            Cred(input.KmsCred), Config(input.ProviderConfig), input.ProjectId, input.Crypt, input.Context, input.Container,
            new List<string>(input.ExpectedKeyRefs));
        var output = await Run(() => Ffi.KiboKmsRestFfiMethods.AppCryptoOpen(native), ct).ConfigureAwait(false);
        return output.plaintext;
    }

    /// <inheritdoc />
    public async Task<FfiCredential> AcquireKmsCredentialAsync(FfiFederationInput input, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        var native = new Ffi.FfiFederationInput(Spec(input.Spec), input.IdentityToken, input.NowUnixSecs);
        var cred = await Run(() => Ffi.KiboKmsRestFfiMethods.AcquireKmsCredential(native), ct).ConfigureAwait(false);
        return new FfiCredential(cred.secret, cred.expiresAtUnixSecs);
    }

    /// <inheritdoc />
    public IReadOnlyList<string> CoreCapabilities() => Ffi.KiboKmsRestFfiMethods.CoreCapabilities();

    /// <summary>Renders an error as <c>"&lt;CODE&gt;: &lt;detail&gt;"</c>.</summary>
    public static string Describe(KError e) => $"{e.Code}: {e.Message}";

    // The binding's calls cannot be cancelled once started; a cancelled caller stops waiting for the answer.
    private static async Task<T> Run<T>(Func<Task<T>> call, CancellationToken ct)
    {
        try { return await call().WaitAsync(ct).ConfigureAwait(false); }
        catch (Ffi.ZkFfiUniffiException e) { throw ToKError(e); }
    }

    /// <summary>Turns an error of the Kibo core into a <see cref="KError"/>; a platform code is kept, your own KMS failing is <c>UPSTREAM_KMS_ERROR</c>.</summary>
    public static KError ToKError(Ffi.ZkFfiUniffiException e) => e switch
    {
        Ffi.ZkFfiUniffiException.PostureViolation pv => new KError(pv.code, pv.detail,
            new Dictionary<string, object?> { ["dimension"] = pv.dimension, ["requested"] = pv.requested, ["declared"] = pv.declared }, null, null, null),
        Ffi.ZkFfiUniffiException.Platform pl => new KError(pl.code, pl.detail),
        Ffi.ZkFfiUniffiException.UpstreamKms uk => new KError("UPSTREAM_KMS_ERROR", uk.detail),
        _ => new KError("KIBO_FFI_ERROR", e.Message),
    };

    private static Ffi.KmsProvider Provider(KmsProviderKind p) => p switch
    {
        KmsProviderKind.AwsKms => Ffi.KmsProvider.AwsKms,
        KmsProviderKind.GcpKms => Ffi.KmsProvider.GcpKms,
        KmsProviderKind.AzureKv => Ffi.KmsProvider.AzureKv,
        KmsProviderKind.HashicorpVault => Ffi.KmsProvider.HashicorpVault,
        _ => throw Bad("provider", p),
    };

    private static Ffi.FfiPosture Posture(PostureKind p) => p switch
    {
        PostureKind.Byok => Ffi.FfiPosture.Byok,
        PostureKind.Hyok => Ffi.FfiPosture.Hyok,
        _ => throw Bad("posture", p),
    };

    private static Ffi.FfiCredential Cred(FfiCredential c) => new(c.Secret, c.ExpiresAtUnixSecs);

    private static Ffi.FfiKeyRef Key(FfiKeyRef k) => new(k.Version, k.ExternalRef);

    private static Ffi.FfiProviderConfig Config(FfiProviderConfig? c) => new(c?.AwsRegion, c?.VaultAddress);

    private static Ffi.FfiFederationSpec Spec(FfiFederationSpec s) => s switch
    {
        FfiFederationSpec.Aws a => new Ffi.FfiFederationSpec.Aws(a.RoleArn, a.SessionName, a.Region, a.KeyArn, a.DurationSecs),
        FfiFederationSpec.Gcp g => new Ffi.FfiFederationSpec.Gcp(g.Audience),
        FfiFederationSpec.Azure z => new Ffi.FfiFederationSpec.Azure(z.TenantId, z.ClientId, z.Scope),
        FfiFederationSpec.Vault v => new Ffi.FfiFederationSpec.Vault(v.VaultAddr, v.JwtAuthMount, v.Role),
        _ => throw Bad("federation", s),
    };

    private static KError Bad(string field, object? value) =>
        new("K9O_INVALID_FIELD_VALUE", $"unknown {field}: {value}", new Dictionary<string, object?> { ["field"] = field }, null, null, null);
}
