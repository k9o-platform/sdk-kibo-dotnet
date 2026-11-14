using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace K9o.Kibo;

// Finds the Kibo core (kibo_kms_rest_ffi) when the host's own probing does not: next to the application, or under runtimes/<rid>/native/.
// A NuGet consumer gets the library through the package; this also covers a library you copied in yourself. The library is only
// looked for when the first call is made, so the package loads without it.
internal static class NativeLoader
{
    private const string Name = "kibo_kms_rest_ffi";

    [ModuleInitializer]
    internal static void Register() => NativeLibrary.SetDllImportResolver(typeof(NativeLoader).Assembly, Resolve);

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != Name) return IntPtr.Zero;
        var file = OperatingSystem.IsWindows() ? Name + ".dll" : OperatingSystem.IsMacOS() ? "lib" + Name + ".dylib" : "lib" + Name + ".so";
        var rid = RuntimeInformation.RuntimeIdentifier;
        var dirs = new[]
        {
            Path.GetDirectoryName(assembly.Location) ?? "",
            AppContext.BaseDirectory,
        };
        foreach (var dir in dirs.Distinct())
        {
            foreach (var path in new[] { Path.Combine(dir, file), Path.Combine(dir, "runtimes", rid, "native", file), Path.Combine(dir, "runtimes", RidFallback(), "native", file) })
                if (File.Exists(path) && NativeLibrary.TryLoad(path, out var handle)) return handle;
        }
        return IntPtr.Zero; // fall back to the default probing
    }

    private static string RidFallback()
    {
        var os = OperatingSystem.IsWindows() ? "win" : OperatingSystem.IsMacOS() ? "osx" : "linux";
        var arch = RuntimeInformation.ProcessArchitecture switch { Architecture.Arm64 => "arm64", Architecture.X86 => "x86", _ => "x64" };
        return $"{os}-{arch}";
    }
}
