using System.Collections.Generic;
using System.Linq;
using System.Text;

using K9o;
using K9o.Kibo.ClientCore;

using Xunit;

namespace K9o.Kibo.Tests;

public class ClientCoreTests
{
    private const string Key = "arn:aws:kms:eu-central-1:111122223333:key/mine";

    private sealed class FakeCore : IAppCore
    {
        public readonly List<string> Log;
        public Func<string[]> Caps = () => new[] { "expected_key_refs" };
        public Func<FfiFederationInput, CancellationToken, Task<FfiCredential>>? Acquire;
        public Func<AppSealInput, Task<byte[]>>? Seal;
        public IReadOnlyCollection<string>? ExportList;
        public FakeCore(List<string> log) { Log = log; }

        public IReadOnlyList<string> CoreCapabilities() => Caps();
        public IReadOnlyCollection<string> Exports => ExportList ?? new[] { "app_crypto_seal", "app_crypto_open", "acquire_kms_credential", "core_capabilities" };

        public Task<FfiCredential> AcquireKmsCredentialAsync(FfiFederationInput input, CancellationToken ct = default)
        {
            Log.Add($"exchange:{input.IdentityToken}");
            return Acquire != null ? Acquire(input, ct) : Task.FromResult(new FfiCredential("cred-1", 10_000));
        }

        public Task<byte[]> AppCryptoSealAsync(AppSealInput input, CancellationToken ct = default)
        {
            Log.Add($"seal:{input.Crypt}:{input.ProjectId}:{string.Join(",", input.ExpectedKeyRefs)}");
            if (Seal != null) return Seal(input);
            return Task.FromResult(new byte[] { 1, 2, 3 }.Concat(input.Plaintext).ToArray());
        }

        public Task<byte[]> AppCryptoOpenAsync(AppOpenInput input, CancellationToken ct = default)
        {
            Log.Add($"open:{input.Crypt}:{string.Join(",", input.ExpectedKeyRefs)}");
            if (input.Container.Length == 0 || input.Container[0] != 1) throw new Exception("K9O_CRYPTO_UNEXPECTED_KEY: no");
            return Task.FromResult(input.Container.Skip(3).ToArray());
        }
    }

    private static CryptoFederatedToken Tok(string? provider = "aws", string? projectId = "proj_1") => new()
    {
        Token = "jwt-secret", ExpiresAt = "x", Issuer = "i", Subject = "proj_1:crypt:c:op:encrypt", Audience = "a", Kid = "k", ProjectId = projectId, Provider = provider,
    };

    private static KiboClientCoreConfig Cfg(List<string> log, FakeCore? core = null, Func<KiboClientCoreConfig, KiboClientCoreConfig>? edit = null)
    {
        var c = new KiboClientCoreConfig
        {
            Provider = KeyRefProvider.Aws,
            Posture = PostureKind.Byok,
            ProjectId = "proj_1",
            KeyRef = new FfiKeyRef(1, Key),
            Federation = new FfiFederationSpec.Aws("arn:aws:iam::1:role/r", "s", "eu-central-1", Key, 900),
            ExpectedKeyRefs = new[] { Key },
            FederatedToken = (crypt, op, _) => { log.Add($"token:{crypt}:{op}"); return Task.FromResult(Tok()); },
            Core = core ?? new FakeCore(log),
            Now = () => 1000,
        };
        return edit == null ? c : edit(c);
    }

    private static readonly CryptoCoreOptions NoOpts = new();
    private static IReadOnlyList<CryptoPlaintext> P(params byte[] b) => new[] { new CryptoPlaintext(b) };

    [Fact]
    public async Task EncryptTokenThenExchangeThenSealAndRoundTripsThroughDecrypt()
    {
        var log = new List<string>();
        var core = new KiboClientCore(Cfg(log));
        var enc = await core.EncryptAsync("c", P(Encoding.UTF8.GetBytes("hi")), NoOpts);
        Assert.Equal(new[] { "token:c:encrypt", "exchange:jwt-secret", $"seal:c:proj_1:{Key}" }, log);
        var dec = await core.DecryptAsync("c", new[] { new CryptoCiphertext(enc.Items[0].Ciphertext!) }, NoOpts);
        Assert.Equal("hi", dec.Items[0].PlaintextString());
    }

    [Fact]
    public void DeclaresItEnforcesThePin() => Assert.True(new KiboClientCore(Cfg(new())).EnforcesExpectedKeyRefs);

    [Fact]
    public void RefusesToBeBuiltWithoutAPinWithAnEmptyPinOrWithAKeyOutsideThePin()
    {
        var none = Assert.Throws<KError>(() => new KiboClientCore(Cfg(new(), null, c => c with { ExpectedKeyRefs = null })));
        Assert.Equal("expectedKeyRefs", none.Context["field"]);
        var empty = Assert.Throws<KError>(() => new KiboClientCore(Cfg(new(), null, c => c with { ExpectedKeyRefs = new string[0] })));
        Assert.Equal("expectedKeyRefs", empty.Context["field"]);
        var e = Assert.Throws<KError>(() => new KiboClientCore(Cfg(new(), null, c => c with { ExpectedKeyRefs = new[] { "arn:aws:kms:eu-central-1:111122223333:key/other" } })));
        Assert.Equal("keyRef", e.Context["field"]);
    }

    [Fact]
    public async Task APerCallPinWithoutTheConfiguredKeyIsRefusedBeforeTokenExchangeSealOrOpen()
    {
        var log = new List<string>();
        var core = new KiboClientCore(Cfg(log));
        var other = new CryptoCoreOptions { ExpectedKeyRefs = new[] { "arn:aws:kms:eu-central-1:111122223333:key/other" } };
        var enc = await core.EncryptAsync("c", new[] { new CryptoPlaintext(new byte[] { 1 }), new CryptoPlaintext(new byte[] { 2 }) }, other);
        Assert.Equal(2, enc.Items.Count);
        Assert.All(enc.Items, i => Assert.Equal("K9O_CRYPTO_UNEXPECTED_KEY", i.Code));
        var dec = await core.DecryptAsync("c", new[] { new CryptoCiphertext("AQID") }, other);
        Assert.Equal("K9O_CRYPTO_UNEXPECTED_KEY", dec.Items[0].Code);
        var rew = await core.RewrapAsync("c", new[] { new CryptoCiphertext("AQID") }, other);
        Assert.Equal("K9O_CRYPTO_UNEXPECTED_KEY", rew.Items[0].Code);
        Assert.Empty(log);
        // a matching per-call pin (any key version) still reaches the token, exchange and seal
        var ok = await core.EncryptAsync("c", P(1), new CryptoCoreOptions { ExpectedKeyRefs = new[] { Key } });
        Assert.NotNull(ok.Items[0].Ciphertext);
        Assert.Equal(new[] { "token:c:encrypt", "exchange:jwt-secret", $"seal:c:proj_1:{Key}" }, log);
    }

    [Fact]
    public async Task AnEmptyPinFromTheRouterReachesNoNetworkAndNoKms()
    {
        var log = new List<string>();
        var core = new KiboClientCore(Cfg(log));
        var e = await Assert.ThrowsAsync<KError>(() => core.DecryptAsync("c", new[] { new CryptoCiphertext("AQID") }, new CryptoCoreOptions { ExpectedKeyRefs = new string[0] }));
        Assert.Contains("key pin", e.Message);
        Assert.Empty(log);
    }

    [Fact]
    public async Task ACoreThatDoesNotListExpectedKeyRefsIsRefusedBeforeAnyTokenIsFetched()
    {
        var log = new List<string>();
        var core = new KiboClientCore(Cfg(log, new FakeCore(log) { Caps = () => new string[0] }));
        var e = await Assert.ThrowsAsync<KError>(() => core.EncryptAsync("c", P(1), NoOpts));
        Assert.Equal("K9O_CRYPTO_KEY_PIN_UNENFORCED", e.Code);
        Assert.Empty(log);
    }

    [Fact]
    public async Task AnOlderCoreWithoutTheNewExportsIsRefused()
    {
        var log = new List<string>();
        var core = new KiboClientCore(Cfg(log, new FakeCore(log) { ExportList = new[] { "core_capabilities" } }));
        var e = await Assert.ThrowsAsync<KError>(() => core.EncryptAsync("c", P(1), NoOpts));
        Assert.Equal("KIBO_WASM_ERROR", e.Code);
        Assert.Empty(log);
    }

    [Theory]
    [InlineData("gcp", "proj_1")]
    [InlineData("aws", "proj_other")]
    public async Task AResponseNamingAnotherProviderOrProjectIsRefusedAndNothingIsExchanged(string provider, string project)
    {
        var log = new List<string>();
        var core = new KiboClientCore(Cfg(log, null, c => c with { FederatedToken = (_, _, _) => Task.FromResult(Tok(provider, project)) }));
        var e = await Assert.ThrowsAsync<KError>(() => core.EncryptAsync("c", P(1), NoOpts));
        Assert.Equal("K9O_INVALID_FIELD_VALUE", e.Code);
        Assert.Empty(log);
    }

    [Fact]
    public async Task ProjectIdComesFromTheResponseOnlyWhenNotConfigured()
    {
        var log = new List<string>();
        var core = new KiboClientCore(Cfg(log, null, c => c with { ProjectId = null }));
        await core.EncryptAsync("c", P(1), NoOpts);
        Assert.Equal($"seal:c:proj_1:{Key}", log.Last());
        var none = new KiboClientCore(Cfg(new(), null, c => c with { ProjectId = null, FederatedToken = (_, _, _) => Task.FromResult(Tok("aws", null)) }));
        var e = await Assert.ThrowsAsync<KError>(() => none.EncryptAsync("c", P(1), NoOpts));
        Assert.Equal("K9O_INVALID_FIELD_VALUE", e.Code);
    }

    [Fact]
    public async Task AResponseWithoutProviderOrProjectIsAccepted()
    {
        var log = new List<string>();
        var core = new KiboClientCore(Cfg(log, null, c => c with { FederatedToken = (_, _, _) => Task.FromResult(Tok(null, null)) }));
        var r = await core.EncryptAsync("c", P(1), NoOpts);
        Assert.NotNull(r.Items[0].Ciphertext);
    }

    [Fact]
    public async Task TheExchangedCredentialIsReusedUntilNearExpiryThenExchangedAgain()
    {
        var log = new List<string>();
        long t = 1000;
        var core = new KiboClientCore(Cfg(log, null, c => c with { Now = () => t }));
        await core.EncryptAsync("c", P(1), NoOpts);
        await core.EncryptAsync("c", P(1), NoOpts);
        Assert.Equal(1, log.Count(l => l.StartsWith("exchange")));
        Assert.Equal(2, log.Count(l => l.StartsWith("token")));
        t = 9_950; // inside the 60 s skew of 10_000
        await core.EncryptAsync("c", P(1), NoOpts);
        Assert.Equal(2, log.Count(l => l.StartsWith("exchange")));
    }

    [Fact]
    public async Task AStalledExchangeIsAbandonedAtTheDeadline()
    {
        var log = new List<string>();
        var fake = new FakeCore(log) { Acquire = (_, _) => new TaskCompletionSource<FfiCredential>().Task };
        var core = new KiboClientCore(Cfg(log, fake, c => c with { ExchangeDeadline = TimeSpan.FromMilliseconds(20) }));
        var e = await Assert.ThrowsAsync<KError>(() => core.EncryptAsync("c", P(1), NoOpts));
        Assert.Equal("KIBO_EXCHANGE_TIMEOUT", e.Code);
        Assert.DoesNotContain("jwt-secret", e.Message);
    }

    [Fact]
    public async Task OneBadItemFailsOnItsOwnAndCarriesTheCoresCodeTheOthersSucceed()
    {
        var core = new KiboClientCore(Cfg(new()));
        var good = (await core.EncryptAsync("c", P(9), NoOpts)).Items[0].Ciphertext!;
        var r = await core.DecryptAsync("c", new[] { new CryptoCiphertext("AAAA"), new CryptoCiphertext(good) }, NoOpts);
        Assert.False(r.Items[0].Ok);
        Assert.Equal("K9O_CRYPTO_UNEXPECTED_KEY", r.Items[0].Code);
        Assert.True(r.Items[1].Ok);
    }

    [Fact]
    public async Task RewrapOpensAndSealsUnderTheConfiguredKeyWithTheRewrapToken()
    {
        var log = new List<string>();
        var core = new KiboClientCore(Cfg(log));
        var ct = (await core.EncryptAsync("c", P(7), NoOpts)).Items[0].Ciphertext!;
        log.Clear();
        var r = await core.RewrapAsync("c", new[] { new CryptoCiphertext(ct) }, NoOpts);
        Assert.True(r.Items[0].Ok);
        Assert.Equal("token:c:rewrap", log[0]);
        Assert.Equal(new[] { "open", "seal" }, log.TakeLast(2).Select(l => l.Split(':')[0]));
    }

    [Fact]
    public async Task UpstreamKmsErrorIsPassedThroughPerItemAndNeitherTokenNorCredentialAppears()
    {
        var log = new List<string>();
        var fake = new FakeCore(log) { Seal = _ => throw new Exception("UPSTREAM_KMS_ERROR: denied") };
        var core = new KiboClientCore(Cfg(log, fake));
        var r = await core.EncryptAsync("c", P(1), NoOpts);
        Assert.Equal("UPSTREAM_KMS_ERROR", r.Items[0].Code);
        Assert.Equal("denied", r.Items[0].Message);
        var s = System.Text.Json.JsonSerializer.Serialize(r);
        Assert.DoesNotContain("jwt-secret", s);
        Assert.DoesNotContain("cred-1", s);
    }

    [Fact]
    public void CredentialsAndTokensAreRedactedInToString()
    {
        var cred = new FfiCredential("cred-1", 5);
        var input = new FfiFederationInput(new FfiFederationSpec.Gcp("aud"), "jwt-secret", 1);
        var seal = new AppSealInput(KmsProviderKind.AwsKms, PostureKind.Byok, cred, new FfiKeyRef(1, Key), new FfiProviderConfig(null, null), "p", "c", null, new byte[] { 1 }, new[] { Key });
        var open = new AppOpenInput(cred, new FfiProviderConfig(null, null), "p", "c", null, new byte[] { 1 }, new[] { Key });
        foreach (var s in new[] { cred.ToString(), input.ToString(), seal.ToString(), open.ToString() })
        {
            Assert.DoesNotContain("cred-1", s);
            Assert.DoesNotContain("jwt-secret", s);
        }
    }

    [Fact]
    public async Task ThePinAndConfigurationReachTheCoreNeverTheResponse()
    {
        var log = new List<string>();
        AppSealInput? seen = null;
        var fake = new FakeCore(log) { Seal = i => { seen = i; return Task.FromResult(new byte[] { 1 }); } };
        var core = new KiboClientCore(Cfg(log, fake, c => c with { ProviderConfig = new FfiProviderConfig("eu-central-1", null) }));
        await core.EncryptAsync("c", P(1), new CryptoCoreOptions { ExpectedKeyRefs = new[] { Key } });
        Assert.Equal(KmsProviderKind.AwsKms, seen!.Provider);
        Assert.Equal(PostureKind.Byok, seen.Posture);
        Assert.Equal("eu-central-1", seen.ProviderConfig.AwsRegion);
        Assert.Equal(new[] { Key }, seen.ExpectedKeyRefs);
    }
}
