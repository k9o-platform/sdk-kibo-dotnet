using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

using K9o;

namespace K9o.Kibo.ClientCore;

// Plain records that mirror the Ffi types of the bound core (kibo-kms-rest-ffi, zk-bundle-v2.16.3). They are kept apart from the generated
// binding (namespace uniffi.kibo_kms_rest_ffi) so this file builds and is tested without the native library. A thin adapter over the
// generated binding satisfies IAppCore: it copies these records into the generated ones, calls AppCryptoSealBlocking-or-async,
// AppCryptoOpenAsync, AcquireKmsCredentialAsync and CoreCapabilities, and copies the results back. Wire names are snake_case.

/// <summary>The customer KMS provider, as the core names it on the wire.</summary>
public enum KmsProviderKind { AwsKms, GcpKms, AzureKv, HashicorpVault }

/// <summary>Byok or Hyok.</summary>
public enum PostureKind { Byok, Hyok }

/// <summary>A short-lived credential for your KMS. <c>ToString()</c> redacts the secret.</summary>
public sealed record FfiCredential(string Secret, ulong ExpiresAtUnixSecs)
{
    private bool PrintMembers(StringBuilder sb) { sb.Append("Secret = <redacted>, ExpiresAtUnixSecs = ").Append(ExpiresAtUnixSecs); return true; }
}

/// <summary>The KMS key version reference.</summary>
public sealed record FfiKeyRef(ulong Version, string ExternalRef);

/// <summary>Provider-specific initialisation; null fields are not used.</summary>
public sealed record FfiProviderConfig(string? AwsRegion, string? VaultAddress);

/// <summary>Which cloud to exchange the identity token with, and how. The values come from the application's own configuration.</summary>
public abstract record FfiFederationSpec
{
    /// <summary>The cloud this spec is for.</summary>
    public abstract KeyRefProvider Provider { get; }

    public sealed record Aws(string RoleArn, string SessionName, string Region, string KeyArn, uint DurationSecs) : FfiFederationSpec
    { public override KeyRefProvider Provider => KeyRefProvider.Aws; }

    public sealed record Gcp(string Audience) : FfiFederationSpec
    { public override KeyRefProvider Provider => KeyRefProvider.Gcp; }

    public sealed record Azure(string TenantId, string ClientId, string Scope) : FfiFederationSpec
    { public override KeyRefProvider Provider => KeyRefProvider.Azure; }

    /// <summary>Vault. <c>JwtAuthMount</c> is the JWT auth mount: the name Vault serves the JWT login under, <c>jwt</c> for <c>auth/jwt</c> (not the transit mount, which comes from the key reference).</summary>
    public sealed record Vault(string VaultAddr, string JwtAuthMount, string Role) : FfiFederationSpec
    { public override KeyRefProvider Provider => KeyRefProvider.Vault; }
}

/// <summary>Input of <c>acquire_kms_credential</c>. <c>ToString()</c> redacts the identity token.</summary>
public sealed record FfiFederationInput(FfiFederationSpec Spec, string IdentityToken, ulong NowUnixSecs)
{
    private bool PrintMembers(StringBuilder sb) { sb.Append("Spec = ").Append(Spec).Append(", IdentityToken = <redacted>, NowUnixSecs = ").Append(NowUnixSecs); return true; }
}

/// <summary>Input of <c>app_crypto_seal</c>.</summary>
public sealed record AppSealInput(
    KmsProviderKind Provider, PostureKind Posture, FfiCredential KmsCred, FfiKeyRef KeyRef, FfiProviderConfig ProviderConfig,
    string ProjectId, string Crypt, string? Context, byte[] Plaintext, IReadOnlyList<string> ExpectedKeyRefs)
{
    private bool PrintMembers(StringBuilder sb) { sb.Append("Crypt = ").Append(Crypt).Append(", ProjectId = ").Append(ProjectId).Append(", (credential and plaintext omitted)"); return true; }
}

/// <summary>Input of <c>app_crypto_open</c>.</summary>
public sealed record AppOpenInput(
    FfiCredential KmsCred, FfiProviderConfig ProviderConfig, string ProjectId, string Crypt, string? Context, byte[] Container,
    IReadOnlyList<string> ExpectedKeyRefs)
{
    private bool PrintMembers(StringBuilder sb) { sb.Append("Crypt = ").Append(Crypt).Append(", ProjectId = ").Append(ProjectId).Append(", (credential omitted)"); return true; }
}

/// <summary>What the bound core exports for the client core. <see cref="FfiAppCore"/> implements it over the native library.</summary>
/// <remarks>
/// Failures are thrown as an exception whose message is <c>"&lt;CODE&gt;: &lt;message&gt;"</c> (or a <see cref="KError"/>);
/// <c>UPSTREAM_KMS_ERROR</c> is your own KMS failing. <see cref="Exports"/> lists the functions the binding really has: an adapter over a
/// binding older than zk-bundle-v2.16.3 leaves out the three new ones and the client core refuses it.
/// </remarks>
public interface IAppCore
{
    /// <summary>Returns the container bytes (<c>0x01 ‖ len ‖ W ‖ D</c>).</summary>
    Task<byte[]> AppCryptoSealAsync(AppSealInput input, CancellationToken ct = default);
    Task<byte[]> AppCryptoOpenAsync(AppOpenInput input, CancellationToken ct = default);
    Task<FfiCredential> AcquireKmsCredentialAsync(FfiFederationInput input, CancellationToken ct = default);
    IReadOnlyList<string> CoreCapabilities();

    /// <summary>Names of the functions this core exports. Default: all four.</summary>
    IReadOnlyCollection<string> Exports => KiboClientCore.RequiredExports;
}

/// <summary>Configuration of the client core. All of it is yours: the platform never supplies any of it.</summary>
public sealed record KiboClientCoreConfig
{
    /// <summary>Your cloud. Must equal <c>Federation.Provider</c>.</summary>
    public KeyRefProvider Provider { get; init; }
    public PostureKind Posture { get; init; }
    /// <summary>The project id (<c>proj_...</c>). Leave out only if you want the token response's value; a value given here is never overridden.</summary>
    public string? ProjectId { get; init; }
    /// <summary>The exact key this application uses.</summary>
    public FfiKeyRef KeyRef { get; init; } = new(0, "");
    /// <summary>Region for AWS, address for Vault.</summary>
    public FfiProviderConfig? ProviderConfig { get; init; }
    /// <summary>How to exchange the platform's identity token for a credential on your cloud.</summary>
    public FfiFederationSpec Federation { get; init; } = null!;
    /// <summary>The keys this application allows. Required and non-empty.</summary>
    public IReadOnlyList<string>? ExpectedKeyRefs { get; init; }
    /// <summary>Fetches the federated token: <c>(crypt, op, ct) =&gt; client.Crypto.FederatedTokenAsync(crypt, op, ct)</c>, unwrapped to its data.</summary>
    public Func<string, string, CancellationToken, Task<CryptoFederatedToken>> FederatedToken { get; init; } = null!;
    /// <summary>The loaded core.</summary>
    public IAppCore Core { get; init; } = null!;
    /// <summary>How long the exchange may take before it is abandoned. Default 30 s.</summary>
    public TimeSpan ExchangeDeadline { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>The host clock, Unix seconds. Default: the system clock.</summary>
    public Func<long>? Now { get; init; }
}

/// <summary>
/// The client core for <c>client.Crypto</c> on a BYOK or HYOK project: opens and seals data on this machine against your own KMS, so the
/// platform never sees plaintext or the key. ZERO crypto here: sealing, opening, the key pin and the token exchange run in the audited Rust
/// core. This class only sequences them: federated token (platform), then <c>acquire_kms_credential</c> (your cloud), then
/// <c>app_crypto_seal</c> / <c>app_crypto_open</c> (your KMS). Register it with <c>client.Crypto.UseClientCore(core)</c>.
/// </summary>
public sealed class KiboClientCore : ICryptoClientCore
{
    /// <summary>Raised when the exchange runs past its deadline.</summary>
    public const string ErrExchangeTimeout = "KIBO_EXCHANGE_TIMEOUT";

    internal static readonly string[] RequiredExports = { "app_crypto_seal", "app_crypto_open", "acquire_kms_credential", "core_capabilities" };

    private const long SkewSecs = 60;
    private static readonly Regex Head = new(@"^([A-Z][A-Z0-9_]*):\s*([\s\S]*)$", RegexOptions.Compiled);

    private readonly KiboClientCoreConfig _c;
    private readonly IReadOnlyList<string> _pin;
    private readonly Func<long> _now;
    private readonly Dictionary<string, FfiCredential> _creds = new();
    private readonly object _lock = new();
    private volatile bool _capsChecked;

    public bool EnforcesExpectedKeyRefs => true;

    public KiboClientCore(KiboClientCoreConfig config)
    {
        _c = config ?? throw Bad("config is required", "config");
        if (_c.Federation == null || _c.Provider != _c.Federation.Provider) throw Bad("provider and federation.provider must be the same cloud", "provider");
        if (!Enum.IsDefined(_c.Provider)) throw Bad("provider must be Aws, Gcp, Azure or Vault", "provider");
        if (!Enum.IsDefined(_c.Posture)) throw Bad("posture must be Byok or Hyok", "posture");
        _pin = CheckPin(_c.ExpectedKeyRefs)
            ?? throw Bad("expectedKeyRefs is required: this client never seals or opens without a key pin", "expectedKeyRefs");
        if (_c.KeyRef == null || !Crypto.KeyRefMatches(_c.KeyRef.ExternalRef ?? "", _pin, _c.Provider)) throw Bad("keyRef is not in expectedKeyRefs", "keyRef");
        if (_c.FederatedToken == null) throw Bad("federatedToken is required", "federatedToken");
        if (_c.Core == null) throw Bad("core is required", "core");
        if (_c.ExchangeDeadline <= TimeSpan.Zero) throw Bad("exchangeDeadline must be positive", "exchangeDeadline");
        _now = _c.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    public async Task<CryptoResult> EncryptAsync(string crypt, IReadOnlyList<CryptoPlaintext> items, CryptoCoreOptions options, CancellationToken ct = default)
    {
        var pin = EffectivePin(options);
        if (!KeyInPin(pin)) return Refused(items.Count);
        var core = CheckCore();
        var (cred, projectId) = await CredentialAsync(core, crypt, "encrypt", ct).ConfigureAwait(false);
        var res = new CryptoResult();
        foreach (var it in items)
        {
            try { res.Items.Add(new CryptoItemResult { Ciphertext = await SealAsync(core, cred, projectId, crypt, it.Plaintext, it.Context, pin, options, ct).ConfigureAwait(false) }); }
            catch (Exception e) when (Itemised(e, ct)) { res.Items.Add(Failure(e)); }
        }
        return res;
    }

    public async Task<CryptoResult> DecryptAsync(string crypt, IReadOnlyList<CryptoCiphertext> items, CryptoCoreOptions options, CancellationToken ct = default)
    {
        var pin = EffectivePin(options);
        if (!KeyInPin(pin)) return Refused(items.Count);
        var core = CheckCore();
        var (cred, projectId) = await CredentialAsync(core, crypt, "decrypt", ct).ConfigureAwait(false);
        var res = new CryptoResult();
        foreach (var it in items)
        {
            try
            {
                var plain = await OpenAsync(core, cred, projectId, crypt, it.Ciphertext, it.Context, pin, options, ct).ConfigureAwait(false);
                res.Items.Add(new CryptoItemResult { Plaintext = Convert.ToBase64String(plain) });
            }
            catch (Exception e) when (Itemised(e, ct)) { res.Items.Add(Failure(e)); }
        }
        return res;
    }

    public async Task<CryptoResult> RewrapAsync(string crypt, IReadOnlyList<CryptoCiphertext> items, CryptoCoreOptions options, CancellationToken ct = default)
    {
        var pin = EffectivePin(options);
        if (!KeyInPin(pin)) return Refused(items.Count);
        var core = CheckCore();
        var (cred, projectId) = await CredentialAsync(core, crypt, "rewrap", ct).ConfigureAwait(false);
        var res = new CryptoResult();
        foreach (var it in items)
        {
            try
            {
                var plain = await OpenAsync(core, cred, projectId, crypt, it.Ciphertext, it.Context, pin, options, ct).ConfigureAwait(false);
                res.Items.Add(new CryptoItemResult { Ciphertext = await SealAsync(core, cred, projectId, crypt, plain, it.Context, pin, options, ct).ConfigureAwait(false) });
            }
            catch (Exception e) when (Itemised(e, ct)) { res.Items.Add(Failure(e)); }
        }
        return res;
    }

    // ---- internals -------------------------------------------------------------------------------------------------

    private static KError Bad(string message, string field) =>
        new("K9O_INVALID_FIELD_VALUE", message, new Dictionary<string, object?> { ["field"] = field }, null, null, null);

    // The root SDK's CheckExpectedKeyRefs is internal, so the same rules are applied here: non-empty, no blank or spaced entry, no wildcard.
    private static IReadOnlyList<string>? CheckPin(IReadOnlyList<string>? refs)
    {
        if (refs == null) return null;
        if (refs.Count == 0) throw Bad("expectedKeyRefs: pass a non-empty list of key identifiers", "expectedKeyRefs");
        foreach (var r in refs)
        {
            if (string.IsNullOrWhiteSpace(r) || r.Any(char.IsWhiteSpace)) throw Bad("expectedKeyRefs: each entry must be a key identifier without spaces", "expectedKeyRefs");
            if (r.Contains('*')) throw Bad("expectedKeyRefs: an entry cannot contain \"*\"; name the exact key", "expectedKeyRefs");
        }
        return new List<string>(refs).AsReadOnly();
    }

    private IReadOnlyList<string> EffectivePin(CryptoCoreOptions? options)
    {
        var p = options?.ExpectedKeyRefs ?? _pin;
        if (p.Count == 0) throw Bad("expectedKeyRefs is empty: refusing to call without a key pin", "expectedKeyRefs");
        return p;
    }

    // The call's own pin is matched against the configured key before any token is fetched or any credential is exchanged; the key version is ignored by the matcher.
    private bool KeyInPin(IReadOnlyList<string> pin) => Crypto.KeyRefMatches(_c.KeyRef.ExternalRef ?? "", pin, _c.Provider);

    private static CryptoResult Refused(int count)
    {
        var res = new CryptoResult();
        for (var i = 0; i < count; i++)
            res.Items.Add(new CryptoItemResult { Code = "K9O_CRYPTO_UNEXPECTED_KEY", Message = "the configured key is not in this call's expectedKeyRefs; nothing was sent" });
        return res;
    }

    private IAppCore CheckCore()
    {
        var w = _c.Core;
        var exports = w.Exports;
        foreach (var fn in RequiredExports)
        {
            if (!exports.Contains(fn))
                throw new KError("KIBO_WASM_ERROR", $"the Kibo core does not export {fn}; it is older than zk-bundle-v2.16.3",
                    new Dictionary<string, object?> { ["missing"] = fn }, "Use a build of K9o.Kibo that ships zk-bundle-v2.16.3 or later.", null, null);
        }
        if (!_capsChecked)
        {
            if (!w.CoreCapabilities().Contains("expected_key_refs"))
                throw new KError(Crypto.KeyPinUnenforcedCode, "the Kibo core does not declare that it enforces expected_key_refs; nothing was sent",
                    new Dictionary<string, object?>(), "Use a build of K9o.Kibo that ships zk-bundle-v2.16.3 or later.", null, null);
            _capsChecked = true;
        }
        return w;
    }

    private static string ProviderName(KeyRefProvider p) => p switch
    {
        KeyRefProvider.Aws => "aws", KeyRefProvider.Gcp => "gcp", KeyRefProvider.Azure => "azure", _ => "vault",
    };

    private static KmsProviderKind Wire(KeyRefProvider p) => p switch
    {
        KeyRefProvider.Aws => KmsProviderKind.AwsKms, KeyRefProvider.Gcp => KmsProviderKind.GcpKms,
        KeyRefProvider.Azure => KmsProviderKind.AzureKv, _ => KmsProviderKind.HashicorpVault,
    };

    private async Task<(FfiCredential cred, string projectId)> CredentialAsync(IAppCore core, string crypt, string op, CancellationToken ct)
    {
        var t = await _c.FederatedToken(crypt, op, ct).ConfigureAwait(false);
        if (t == null || string.IsNullOrEmpty(t.Token)) throw new KError("KIBO_WASM_DECODE_ERROR", "the federated token answer carries no token");
        if (t.Provider != null && t.Provider != ProviderName(_c.Provider))
            throw Bad($"the platform named provider \"{t.Provider}\"; this client is configured for \"{ProviderName(_c.Provider)}\"", "provider");
        if (t.ProjectId != null && _c.ProjectId != null && t.ProjectId != _c.ProjectId)
            throw Bad("the platform named a different project than the one configured", "projectId");
        var projectId = _c.ProjectId ?? t.ProjectId;
        if (projectId == null) throw Bad("projectId is not configured and the platform did not name one", "projectId");

        var cacheKey = $"{crypt}\u0000{op}\u0000{t.Subject}";
        // A token is fetched on every call (it is bound to the call's crypt and op); the credential from the exchange is reused until it is close to expiring.
        lock (_lock)
        {
            if (_creds.TryGetValue(cacheKey, out var cached) && (long)cached.ExpiresAtUnixSecs - SkewSecs > _now())
                return (cached, projectId);
        }

        FfiCredential cred;
        try { cred = await ExchangeAsync(core, new FfiFederationInput(_c.Federation, t.Token!, (ulong)_now()), ct).ConfigureAwait(false); }
        catch (Exception e) when (Itemised(e, ct)) { throw MapCoreError(e); }
        if (cred == null || string.IsNullOrEmpty(cred.Secret))
            throw new KError("KIBO_WASM_DECODE_ERROR", "the core returned a credential without secret or expiry");
        lock (_lock) _creds[cacheKey] = cred;
        return (cred, projectId);
    }

    // The exchange runs under a deadline: a core that stalls (or never answers) is abandoned and its token cancelled.
    private async Task<FfiCredential> ExchangeAsync(IAppCore core, FfiFederationInput input, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var work = Task.Run(() => core.AcquireKmsCredentialAsync(input, cts.Token), CancellationToken.None);
        var timer = Task.Delay(_c.ExchangeDeadline, cts.Token);
        var done = await Task.WhenAny(work, timer).ConfigureAwait(false);
        if (done == work)
        {
            cts.Cancel();
            return await work.ConfigureAwait(false);
        }
        ct.ThrowIfCancellationRequested();
        cts.Cancel();
        _ = work.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted); // observe a late failure
        var ms = (long)_c.ExchangeDeadline.TotalMilliseconds;
        throw new KError(ErrExchangeTimeout, $"the token exchange with your cloud did not finish within {ms} ms",
            new Dictionary<string, object?> { ["deadlineMs"] = ms }, "Check that your cloud's token endpoint is reachable from this host.", null, null);
    }

    private FfiProviderConfig PConfig(CryptoCoreOptions? options) => new(
        _c.ProviderConfig?.AwsRegion, _c.ProviderConfig?.VaultAddress);

    private async Task<string> SealAsync(IAppCore core, FfiCredential cred, string projectId, string crypt, byte[] plaintext, string? context,
        IReadOnlyList<string> pin, CryptoCoreOptions? options, CancellationToken ct)
    {
        var container = await core.AppCryptoSealAsync(new AppSealInput(Wire(_c.Provider), _c.Posture, cred, _c.KeyRef, PConfig(options), projectId, crypt, context, plaintext, pin.ToArray()), ct).ConfigureAwait(false);
        return Convert.ToBase64String(container ?? throw new KError("KIBO_WASM_DECODE_ERROR", "the core returned no container"));
    }

    private async Task<byte[]> OpenAsync(IAppCore core, FfiCredential cred, string projectId, string crypt, string ciphertext, string? context,
        IReadOnlyList<string> pin, CryptoCoreOptions? options, CancellationToken ct)
    {
        byte[] container;
        try { container = Convert.FromBase64String(ciphertext); }
        catch (FormatException) { throw new KError("K9O_INVALID_FIELD_VALUE", "ciphertext is not base64"); }
        var plain = await core.AppCryptoOpenAsync(new AppOpenInput(cred, PConfig(options), projectId, crypt, context, container, pin.ToArray()), ct).ConfigureAwait(false);
        return plain ?? throw new KError("KIBO_WASM_DECODE_ERROR", "the core returned no plaintext");
    }

    // A caller's own cancellation is never turned into an item failure or a core error.
    private static bool Itemised(Exception e, CancellationToken ct) => !(e is OperationCanceledException && ct.IsCancellationRequested);

    /// <summary>The core fails with "&lt;CODE&gt;: &lt;message&gt;"; UPSTREAM_KMS_ERROR is your own KMS failing.</summary>
    private static KError MapCoreError(Exception e)
    {
        if (e is KError k) return k;
        var raw = e.Message ?? e.GetType().Name;
        var m = Head.Match(raw);
        return m.Success ? new KError(m.Groups[1].Value, m.Groups[2].Value) : new KError("KIBO_WASM_ERROR", raw);
    }

    private static CryptoItemResult Failure(Exception e)
    {
        var k = MapCoreError(e);
        return new CryptoItemResult { Code = k.Code, Message = k.Message };
    }
}
