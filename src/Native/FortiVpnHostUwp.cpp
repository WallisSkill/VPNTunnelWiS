// The host process the VPN platform launches for a vpnClient background task.
//
// It replaces the .NET console host, which Windows refused to start at all
// (E_APPLICATION_ACTIVATION_EXEC_FAILURE, 0x8027025B): a packaged app launched by the
// app model has to complete the activation handshake, and that handshake happens inside
// CoreApplication::Run. Nothing here registers activation factories -- the plugin class
// is declared as an inProcessServer, so combase creates it inside this process when the
// platform asks for it. That is why the manifest must not declare it out-of-process.
//
// There is deliberately no window and no UI: the view exists only because
// CoreApplication::Run demands one.

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.ApplicationModel.Core.h>
#include <winrt/Windows.ApplicationModel.Activation.h>
#include <winrt/Windows.UI.Core.h>

#include <windows.h>
#include <string>

using namespace winrt;
using namespace winrt::Windows::ApplicationModel::Core;
using namespace winrt::Windows::UI::Core;

namespace
{
    void Trace(std::wstring const& line)
    {
        wchar_t dir[MAX_PATH]{};
        if (!GetTempPathW(MAX_PATH, dir)) return;

        std::wstring path = std::wstring(dir) + L"forti-host.log";
        HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return;

        SYSTEMTIME now{};
        GetLocalTime(&now);

        wchar_t buffer[1024]{};
        int count = swprintf_s(buffer, L"%02d:%02d:%02d.%03d %s\r\n",
                               now.wHour, now.wMinute, now.wSecond, now.wMilliseconds, line.c_str());

        char utf8[2048]{};
        int bytes = WideCharToMultiByte(CP_UTF8, 0, buffer, count, utf8, sizeof(utf8), nullptr, nullptr);
        DWORD written = 0;
        WriteFile(file, utf8, static_cast<DWORD>(bytes), &written, nullptr);
        CloseHandle(file);
    }

    struct View : implements<View, IFrameworkViewSource, IFrameworkView>
    {
        IFrameworkView CreateView() { return *this; }

        void Initialize(CoreApplicationView const& view)
        {
            Trace(L"Initialize");
            // Background activation is the only kind this app ever sees. Logging it
            // separates "the platform never called us" from "it called us and the
            // plugin class failed to create".
            view.Activated([](auto const&, auto const& args)
            {
                Trace(L"Activated: kind=" + std::to_wstring(static_cast<int>(args.Kind())));
            });
        }

        void SetWindow(CoreWindow const&) { Trace(L"SetWindow"); }
        void Load(hstring const&) { Trace(L"Load"); }

        void Run()
        {
            // On the multi-threaded apartment there is no CoreWindow to pump, and there
            // is nothing to pump anyway: the platform activates the plugin class through
            // COM, on its own threads. Blocking keeps the process alive for it.
            if (auto window = CoreWindow::GetForCurrentThread())
            {
                Trace(L"Run: pumping the CoreWindow event loop");
                window.Dispatcher().ProcessEvents(CoreProcessEventsOption::ProcessUntilQuit);
            }
            else
            {
                Trace(L"Run: no CoreWindow, waiting");
                SleepEx(INFINITE, TRUE);
            }
            Trace(L"Run: exiting");
        }

        void Uninitialize() { Trace(L"Uninitialize"); }
    };
}

int __stdcall wWinMain(HINSTANCE, HINSTANCE, PWSTR commandLine, int)
{
    Trace(std::wstring(L"wWinMain: ") + (commandLine ? commandLine : L"<no arguments>"));
    try
    {
        // Multi-threaded on purpose: launched as a background server, the first touch of
        // the application object has to come from the MTA, and an STA here fails with
        // "The Application Object must initially be accessed from the multi-thread
        // apartment."
        init_apartment(apartment_type::multi_threaded);
        CoreApplication::Run(make<View>());
    }
    catch (hresult_error const& e)
    {
        Trace(L"CoreApplication::Run nem: " + std::wstring(e.message()));
        return static_cast<int>(e.code());
    }
    Trace(L"thoat binh thuong");
    return 0;
}
