using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using K9o;
using K9o.Kibo.ClientCore;

using Xunit;

namespace K9o.Kibo.Tests;

public class FfiAppCoreTests
{
    private static readonly FfiAppCore Core = new();
    private static readonly FfiCredential Cred = new("placeholder-secret", (ulong)DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds());

    [Fact]
    public void CreatingTheAdapterDoesNotTouchTheNativeLibrary()
    {
        IAppCore core = new FfiAppCore();
        Assert.Equal(4, core.Exports.Count);
    }

    [Fact]
    public void ErrorsAreRenderedAsCodeAndDetail()
    {
        var e = FfiAppCore.ToKError(new uniffi.kibo_kms_rest_ffi.ZkFfiUniffiException.Platform("K9O_CRYPTO_UNEXPECTED_KEY", "not in the pin"));
        Assert.Equal("K9O_CRYPTO_UNEXPECTED_KEY: not in the pin", FfiAppCore.Describe(e));
        var u = FfiAppCore.ToKError(new uniffi.kibo_kms_rest_ffi.ZkFfiUniffiException.UpstreamKms("denied"));
        Assert.Equal("UPSTREAM_KMS_ERROR: denied", FfiAppCore.Describe(u));
        var p = FfiAppCore.ToKError(new uniffi.kibo_kms_rest_ffi.ZkFfiUniffiException.PostureViolation("K9O_CRYPTO_POSTURE_FLOOR_VIOLATION", "d", "custody_posture", "byok", "hyok"));
        Assert.Equal("hyok", p.Context["declared"]);
    }

    [NativeFact]
    public void CoreListsExpectedKeyRefs()
    {
        Assert.Contains("expected_key_refs", Core.CoreCapabilities());
    }

    [NativeFact]
    public async Task CoreRefusalOfAKeyOutsideThePinComesBackAsCodeAndDetail()
    {
        var input = Seal(KmsProviderKind.AwsKms, new FfiKeyRef(1, "arn:aws:kms:us-east-1:111122223333:key/abc"),
            new FfiProviderConfig("us-east-1", null), new[] { "arn:aws:kms:us-east-1:111122223333:key/other" });
        var e = await Assert.ThrowsAsync<KError>(() => Core.AppCryptoSealAsync(input));
        Assert.Equal("K9O_CRYPTO_UNEXPECTED_KEY", e.Code);
        Assert.StartsWith("K9O_CRYPTO_UNEXPECTED_KEY: ", FfiAppCore.Describe(e));
    }

    [NativeNetworkFact]
    public Task AwsSealIsRefusedByTheProvider() => ExpectUpstream(Seal(KmsProviderKind.AwsKms,
        new FfiKeyRef(1, "arn:aws:kms:us-east-1:111122223333:key/abc"), new FfiProviderConfig("us-east-1", null),
        new[] { "arn:aws:kms:us-east-1:111122223333:key/abc" }));

    [NativeNetworkFact]
    public Task GcpSealIsRefusedByTheProvider() => ExpectUpstream(Seal(KmsProviderKind.GcpKms,
        new FfiKeyRef(1, "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"), new FfiProviderConfig(null, null),
        new[] { "projects/p/locations/global/keyRings/r/cryptoKeys/k" }));

    [NativeNetworkFact]
    public Task AzureSealIsRefusedByTheProvider() => ExpectUpstream(Seal(KmsProviderKind.AzureKv,
        new FfiKeyRef(1, "https://example-vault.vault.azure.net/keys/k/0123456789abcdef"), new FfiProviderConfig(null, null),
        new[] { "https://example-vault.vault.azure.net/keys/k" }));

    [NativeFact]
    public async Task VaultSealReachesTheVaultAndIsRefused()
    {
        using var stub = new Stub();
        var input = Seal(KmsProviderKind.HashicorpVault, new FfiKeyRef(1, "transit/keys/orders:1"), new FfiProviderConfig(null, stub.Address),
            new[] { "transit/keys/orders" });
        await ExpectUpstream(input);
        Assert.NotEmpty(stub.Requests);
        Assert.Contains("/v1/transit/", stub.Requests[0]);
    }

    [NativeFact]
    public async Task VaultLoginGoesToTheJwtAuthMount()
    {
        using var stub = new Stub();
        var spec = new FfiFederationSpec.Vault(stub.Address, "my-jwt", "app-role");
        var e = await Assert.ThrowsAsync<KError>(() => Core.AcquireKmsCredentialAsync(new FfiFederationInput(spec, "placeholder-jwt", 1_000_000)));
        Assert.Equal("UPSTREAM_KMS_ERROR", e.Code);
        Assert.StartsWith("UPSTREAM_KMS_ERROR: ", FfiAppCore.Describe(e));
        Assert.Contains(stub.Requests, r => r.StartsWith("POST /v1/auth/my-jwt/login "));
    }

    [NativeFact]
    public async Task ClientCoreExchangeFailureCarriesTheCoreCode()
    {
        using var stub = new Stub();
        var key = "transit/keys/orders:1";
        var cfg = new KiboClientCoreConfig
        {
            Provider = KeyRefProvider.Vault, Posture = PostureKind.Byok, ProjectId = "proj_1", KeyRef = new FfiKeyRef(1, key),
            ProviderConfig = new FfiProviderConfig(null, stub.Address),
            Federation = new FfiFederationSpec.Vault(stub.Address, "jwt", "r"),
            ExpectedKeyRefs = new[] { "transit/keys/orders" },
            FederatedToken = (c, o, ct) => Task.FromResult(new CryptoFederatedToken { Token = "placeholder-jwt", Subject = "s", ProjectId = "proj_1", Provider = "vault" }),
            Core = Core,
        };
        var e = await Assert.ThrowsAsync<KError>(() =>
            new KiboClientCore(cfg).EncryptAsync("c", new[] { new CryptoPlaintext(new byte[] { 1 }) }, new CryptoCoreOptions()));
        Assert.Equal("UPSTREAM_KMS_ERROR", e.Code);
        Assert.Contains(stub.Requests, r => r.StartsWith("POST /v1/auth/jwt/login "));
    }

    private static async Task ExpectUpstream(AppSealInput input)
    {
        var e = await Assert.ThrowsAsync<KError>(() => Core.AppCryptoSealAsync(input));
        Assert.Equal("UPSTREAM_KMS_ERROR", e.Code);
        Assert.StartsWith("UPSTREAM_KMS_ERROR: ", FfiAppCore.Describe(e));
    }

    private static AppSealInput Seal(KmsProviderKind p, FfiKeyRef key, FfiProviderConfig cfg, string[] pin) =>
        new(p, PostureKind.Byok, Cred, key, cfg, "proj_1", "c", null, new byte[] { 1, 2, 3 }, pin);

    // A loopback server that answers every request with 403 and records the request line.
    private sealed class Stub : IDisposable
    {
        private readonly HttpListener _l = new();
        public readonly List<string> Requests = new();
        public string Address { get; }

        public Stub()
        {
            var port = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            port.Start();
            var n = ((IPEndPoint)port.LocalEndpoint).Port;
            port.Stop();
            Address = $"http://127.0.0.1:{n}";
            _l.Prefixes.Add(Address + "/");
            _l.Start();
            _ = Task.Run(async () =>
            {
                while (_l.IsListening)
                {
                    HttpListenerContext c;
                    try { c = await _l.GetContextAsync(); } catch { return; }
                    lock (Requests) Requests.Add($"{c.Request.HttpMethod} {c.Request.RawUrl} HTTP/{c.Request.ProtocolVersion}");
                    c.Response.StatusCode = 403;
                    var body = Encoding.UTF8.GetBytes("{\"errors\":[\"permission denied\"]}");
                    c.Response.ContentType = "application/json";
                    await c.Response.OutputStream.WriteAsync(body);
                    c.Response.Close();
                }
            });
        }

        public void Dispose() { try { _l.Stop(); _l.Close(); } catch { } }
    }
}
