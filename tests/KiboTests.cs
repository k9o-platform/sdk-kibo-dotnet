using System.Collections.Generic;

using K9o;
using uniffi.kibo_kms_rest_ffi;

using Xunit;

namespace K9o.Kibo.Tests;

// The crypto round-trip needs real customer-KMS creds and is exercised by the
// staging conformance ZK step; here we pin the boundary the wrapper owns — the
// posture-floor rejection (enforced by the core pre-KMS), which round-trips
// through the SYNC ZkEncryptBlocking export and maps to a typed K9o.KError. Needs
// the native library (skipped when it cannot be loaded); the identical behaviour is proven against the real
// core in the Ruby + Python + Go suites.
public class KiboTests
{
    [NativeFact]
    public void PostureFloorViolationMapsToKError()
    {
        var input = new EncryptInput(
            KmsProvider.AwsKms,
            FfiPosture.Byok,
            null,
            null,
            new FfiCredential("t", 0),
            new FfiKeyRef(1, "arn:aws:kms:us-east-1:0:key/abc"),
            new FfiProviderConfig("us-east-1", null),
            FfiAttestationTier.Software,
            new List<FfiKvPair>(),
            new byte[] { 104, 105 },
            // BYOK requested, HYOK floor declared -> violation (rejected pre-KMS).
            new FfiPosturePolicy(FfiMinPosture.Hyok, new FfiAllowedOracleModes(true, true)),
            new List<string>()
        );

        var ex = Assert.Throws<KError>(() => Kibo.Encrypt(input));
        Assert.Equal("K9O_CRYPTO_POSTURE_FLOOR_VIOLATION", ex.Code);
        Assert.Equal("custody_posture", ex.Context["dimension"]);
        Assert.Equal("byok", ex.Context["requested"]);
    }
}
