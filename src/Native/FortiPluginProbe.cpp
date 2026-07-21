// A deliberately empty VPN plugin, built as a native in-process WinRT server.
//
// It answers one question that the C# package could not: does Windows accept a
// vpnClient background task hosted in-process -- no ServerName, no custom host -- when
// the class comes from a plain WinRT DLL rather than from WinRT.Host.dll? Every
// manifest shape tried with the managed package ran into the same contradiction: the
// task type demands a custom host, the entry point class must be registered
// in-process, and one class cannot be registered in both places.
//
// So this does nothing but exist and be activated. It writes a line to
// %TEMP%\forti-probe.log on every callback, and %TEMP% inside the package points at
// the package's own temp folder, which the app container can write to.

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Networking.Vpn.h>
#include <winrt/Windows.ApplicationModel.Background.h>

#include <windows.h>
#include <string>

using namespace winrt;
using namespace winrt::Windows::Foundation;
using namespace winrt::Windows::Networking::Vpn;

namespace
{
    void Trace(wchar_t const* line)
    {
        wchar_t dir[MAX_PATH]{};
        if (!GetTempPathW(MAX_PATH, dir)) return;

        std::wstring path = std::wstring(dir) + L"forti-probe.log";
        HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return;

        SYSTEMTIME now{};
        GetLocalTime(&now);

        wchar_t buffer[512]{};
        int count = swprintf_s(buffer, L"%02d:%02d:%02d.%03d %s\r\n",
                               now.wHour, now.wMinute, now.wSecond, now.wMilliseconds, line);

        // The log is read from outside the container, so it is written as UTF-8 rather
        // than UTF-16: one less thing to get wrong when reading it back.
        char utf8[1024]{};
        int bytes = WideCharToMultiByte(CP_UTF8, 0, buffer, count, utf8, sizeof(utf8), nullptr, nullptr);
        DWORD written = 0;
        WriteFile(file, utf8, static_cast<DWORD>(bytes), &written, nullptr);
        CloseHandle(file);
    }

    // IBackgroundTask as well as IVpnPlugIn: the background task infrastructure activates
    // this class as a task first and only then hands it to the VPN platform, so a class
    // that implements only IVpnPlugIn is answered with E_NOINTERFACE and the dial dies
    // before Connect is ever reached.
    struct FortiPlugin : implements<FortiPlugin, IVpnPlugIn,
                                    winrt::Windows::ApplicationModel::Background::IBackgroundTask>
    {
        FortiPlugin() { Trace(L"FortiPlugin constructed."); }

        void Run(winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance const& task)
        {
            Trace(L"IBackgroundTask::Run");
            // Handing the trigger details back to the VPN platform is what turns this
            // background activation into VPN callbacks; without it the task simply ends
            // and the dial sits at "Verifying username and password" until it times out.
            VpnChannel::ProcessEventAsync(*this, task.TriggerDetails());
            Trace(L"ProcessEventAsync returned");
        }

        void Connect(VpnChannel const& channel)
        {
            Trace(L"Connect");
            // Nothing to connect to. Failing here still proves the platform got this far,
            // and it fails the dial cleanly instead of leaving a half-built tunnel.
            channel.LogDiagnosticMessage(L"forti probe: Connect was reached");
            throw hresult_not_implemented();
        }

        void Disconnect(VpnChannel const&) { Trace(L"Disconnect"); }

        void GetKeepAlivePayload(VpnChannel const&, VpnPacketBuffer& keepAlivePacket)
        {
            Trace(L"GetKeepAlivePayload");
            keepAlivePacket = nullptr;
        }

        void Encapsulate(VpnChannel const&, VpnPacketBufferList const&, VpnPacketBufferList const&)
        {
            Trace(L"Encapsulate");
        }

        void Decapsulate(VpnChannel const&, VpnPacketBuffer const&, VpnPacketBufferList const&,
                         VpnPacketBufferList const&)
        {
            Trace(L"Decapsulate");
        }
    };

    struct FortiPluginFactory : implements<FortiPluginFactory, IActivationFactory>
    {
        IInspectable ActivateInstance()
        {
            Trace(L"ActivateInstance");
            return make<FortiPlugin>().as<IInspectable>();
        }
    };
}

extern "C" HRESULT __stdcall DllGetActivationFactory(void* classId, void** factory) noexcept
{
    try
    {
        // The classId is an HSTRING the caller still owns, so it is read through a
        // borrowed hstring rather than constructed into one; this is the shape
        // cppwinrt's own generated entry point uses.
        std::wstring_view const name{ *reinterpret_cast<hstring const*>(&classId) };
        Trace((L"DllGetActivationFactory(" + std::wstring(name) + L")").c_str());

        if (name == L"FortiVpnPlugin.FortiPlugin")
        {
            *factory = detach_abi(make<FortiPluginFactory>());
            return S_OK;
        }

        *factory = nullptr;
        return hresult_class_not_available().to_abi();
    }
    catch (...)
    {
        return to_hresult();
    }
}

// No noexcept: combaseapi.h already declares this one, without it, and the two
// declarations have to agree.
extern "C" HRESULT __stdcall DllCanUnloadNow()
{
    // Staying loaded costs nothing here and avoids being torn down between callbacks.
    return S_FALSE;
}
