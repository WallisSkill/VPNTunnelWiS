using System;
using System.Runtime.InteropServices;
using WinRT;

namespace FortiVpnPlugin
{
    /// <summary>
    /// The bridge the native in-process server calls into.
    ///
    /// It exists because WinRT.Host.dll -- the stock CsWinRT host that is supposed to do
    /// exactly this -- answers every activation with 0x80008093 on this machine, before it
    /// ever starts a runtime. Starting the runtime by hand through hostfxr works, so the
    /// shim does that instead and asks this method for the object. From here on everything
    /// is ordinary CsWinRT: the returned pointer is a real WinRT object that the VPN
    /// platform can QueryInterface for IVpnPlugIn and IBackgroundTask.
    /// </summary>
    // Internal on purpose: a public type in a CsWinRT component has to be a valid WinRT
    // type, and a method taking a raw pointer is not. hostfxr finds it by name regardless.
    internal static unsafe class Exports
    {
        /// <summary>
        /// Creates a <see cref="FortiPlugin"/> and hands out its WinRT ABI pointer with a
        /// reference already added -- the caller owns that reference and releases it.
        /// </summary>
        [UnmanagedCallersOnly]
        public static int CreateInstance(IntPtr* result)
        {
            try
            {
                *result = MarshalInspectable<FortiPlugin>.FromManaged(new FortiPlugin());
                return 0;
            }
            catch (Exception ex)
            {
                *result = IntPtr.Zero;
                return ex.HResult;
            }
        }
    }
}
