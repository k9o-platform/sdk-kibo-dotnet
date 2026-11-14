using System;
using System.Collections.Generic;

using uniffi.kibo_kms_rest_ffi;

using Xunit;

namespace K9o.Kibo.Tests;

// The tests that call the real core need the native library next to the test binaries. When it cannot be loaded they are skipped, not failed.
internal static class Native
{
    public static readonly Lazy<string?> LoadError = new(() =>
    {
        try { KiboKmsRestFfiMethods.CoreCapabilities(); return null; }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException or TypeInitializationException)
        {
            return e.GetBaseException().Message;
        }
    });

    public static bool Available => LoadError.Value == null;

    public static bool NetworkEnabled => Environment.GetEnvironmentVariable("K9O_KIBO_CORE_NETWORK_TESTS") == "1";
}

/// <summary>A test that needs the native library; skipped when it cannot be loaded.</summary>
public sealed class NativeFactAttribute : FactAttribute
{
    public NativeFactAttribute()
    {
        if (!Native.Available) Skip = "the native library kibo_kms_rest_ffi cannot be loaded";
    }
}

/// <summary>A test that needs the native library and reaches a cloud provider's public host; also needs K9O_KIBO_CORE_NETWORK_TESTS=1.</summary>
public sealed class NativeNetworkFactAttribute : FactAttribute
{
    public NativeNetworkFactAttribute()
    {
        if (!Native.Available) Skip = "the native library kibo_kms_rest_ffi cannot be loaded";
        else if (!Native.NetworkEnabled) Skip = "set K9O_KIBO_CORE_NETWORK_TESTS=1 to reach the providers' public hosts";
    }
}
