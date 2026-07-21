// The in-process WinRT server the VPN platform activates: a native DLL that starts
// CoreCLR itself and hands out the managed FortiPlugin object.
//
// The stock way to do this is WinRT.Host.dll from CsWinRT, and it does not work here: it
// answers every DllGetActivationFactory with 0x80008093 without starting a runtime at all
// (and, when named directly in the manifest, the platform reports the failure as the far
// less helpful 0x80073CFC). Driving hostfxr by hand does work -- the runtime starts and
// hands over the load-assembly delegate -- so that is what this does. Everything past
// ActivateInstance is ordinary CsWinRT: the pointer it returns is a real WinRT object and
// the platform gets IVpnPlugIn and IBackgroundTask off it the usual way.

#include <windows.h>
#include <winstring.h>
#include <inspectable.h>
#include <activation.h>
#include <string>

namespace
{
    void Trace(std::wstring const& line)
    {
        wchar_t dir[MAX_PATH]{};
        if (!GetTempPathW(MAX_PATH, dir)) return;

        std::wstring path = std::wstring(dir) + L"forti-shim.log";
        HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return;

        SYSTEMTIME now{};
        GetLocalTime(&now);

        wchar_t buffer[1024]{};
        int count = swprintf_s(buffer, L"%02d:%02d:%02d.%03d %s\r\n",
                               now.wHour, now.wMinute, now.wSecond, now.wMilliseconds, line.c_str());

        // Written as UTF-8 so it reads cleanly from outside the app container.
        char utf8[2048]{};
        int bytes = WideCharToMultiByte(CP_UTF8, 0, buffer, count, utf8, sizeof(utf8), nullptr, nullptr);
        DWORD written = 0;
        WriteFile(file, utf8, static_cast<DWORD>(bytes), &written, nullptr);
        CloseHandle(file);
    }

    std::wstring Hex(unsigned long value)
    {
        wchar_t text[16]{};
        swprintf_s(text, L"0x%08lX", value);
        return text;
    }

    HMODULE g_self = nullptr;

    // The managed side: FortiVpnPlugin.Exports.CreateInstance, an UnmanagedCallersOnly
    // method that news up a FortiPlugin and returns its ABI pointer with a reference added.
    using CreateInstanceFn = int(__stdcall*)(void**);
    CreateInstanceFn g_create = nullptr;

    using GetHostfxrPath = int(__stdcall*)(wchar_t*, size_t*, void const*);
    using InitForConfig = int(__stdcall*)(wchar_t const*, void const*, void**);
    using InitForCommandLine = int(__stdcall*)(int, wchar_t const**, void const*, void**);
    using GetDelegate = int(__stdcall*)(void*, int, void**);
    using CloseContext = int(__stdcall*)(void*);
    using LoadAssembly = int(__stdcall*)(wchar_t const*, wchar_t const*, wchar_t const*,
                                         wchar_t const*, void*, void**);

    std::wstring OwnDirectory()
    {
        wchar_t self[MAX_PATH]{};
        GetModuleFileNameW(g_self, self, MAX_PATH);
        std::wstring dir{ self };
        dir.resize(dir.find_last_of(L'\\') + 1);
        return dir;
    }

    // nethost.dll is not part of the publish output, so the fxr directory is walked
    // directly. Newest version wins, which is what nethost would have picked anyway.
    //
    // The package's own copy comes first. The layout is a self-contained publish, so the
    // whole runtime is already sitting next to this DLL, and using it is what lets the
    // package run on a machine with no .NET installed at all. Falling back to the
    // machine-wide install keeps a hand-assembled layout working.
    std::wstring FindHostfxr()
    {
        std::wstring const local = OwnDirectory() + L"hostfxr.dll";
        if (GetFileAttributesW(local.c_str()) != INVALID_FILE_ATTRIBUTES) return local;

        std::wstring const root = L"C:\\Program Files\\dotnet\\host\\fxr\\";
        WIN32_FIND_DATAW found{};
        HANDLE search = FindFirstFileW((root + L"*").c_str(), &found);
        if (search == INVALID_HANDLE_VALUE) return {};

        std::wstring best;
        do
        {
            if (!(found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (found.cFileName[0] == L'.') continue;
            if (best.empty() || wcscmp(found.cFileName, best.c_str()) > 0) best = found.cFileName;
        } while (FindNextFileW(search, &found));
        FindClose(search);

        if (best.empty()) return {};
        return root + best + L"\\hostfxr.dll";
    }

    // Started once and never shut down: the runtime lives as long as the host process, and
    // the platform activates the plugin repeatedly over a single dial.
    bool StartRuntime()
    {
        if (g_create) return true;

        std::wstring const dir = OwnDirectory();
        std::wstring const fxr = FindHostfxr();
        if (fxr.empty()) { Trace(L"hostfxr not found"); return false; }
        Trace(L"hostfxr: " + fxr);

        HMODULE module = LoadLibraryExW(fxr.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!module) { Trace(L"loading hostfxr failed: " + Hex(GetLastError())); return false; }

        auto init = reinterpret_cast<InitForConfig>(GetProcAddress(module, "hostfxr_initialize_for_runtime_config"));
        auto initApp = reinterpret_cast<InitForCommandLine>(GetProcAddress(module, "hostfxr_initialize_for_dotnet_command_line"));
        auto get = reinterpret_cast<GetDelegate>(GetProcAddress(module, "hostfxr_get_runtime_delegate"));
        auto close = reinterpret_cast<CloseContext>(GetProcAddress(module, "hostfxr_close"));
        if (!init || !initApp || !get || !close) { Trace(L"hostfxr entry point missing"); return false; }

        // The app path, not the plugin: it is the self-contained publish output, so its
        // runtimeconfig names the runtime lying in this same folder and its deps.json lists
        // every assembly in it. Nothing of the app is run -- initialising is all that is
        // wanted, and the runtime it brings up is the one the plugin then loads into.
        std::wstring const app = dir + L"FortiVpnHost.dll";
        wchar_t const* argv[]{ app.c_str() };

        // A self-contained runtimeconfig is rejected outright by the config entry point
        // (0x80008093, HostApiUnsupportedScenario): it has no framework reference to
        // resolve, only an included one. The command-line entry point is the way in for
        // that shape, and it is what removes the need for any machine-wide .NET at all.
        // The config route stays first so a framework-dependent layout still starts.
        void* context = nullptr;
        int rc = init((dir + L"FortiVpnPlugin.runtimeconfig.json").c_str(), nullptr, &context);
        Trace(L"hostfxr_initialize_for_runtime_config -> " + Hex(static_cast<unsigned long>(rc)));
        if (rc < 0 || !context)
        {
            if (context) { close(context); context = nullptr; }
            rc = initApp(1, argv, nullptr, &context);
            Trace(L"hostfxr_initialize_for_dotnet_command_line -> " + Hex(static_cast<unsigned long>(rc)));
            if (rc < 0 || !context) { if (context) close(context); return false; }
        }

        void* loader = nullptr;
        // 5 == hdt_load_assembly_and_get_function_pointer.
        rc = get(context, 5, &loader);
        close(context);
        Trace(L"hostfxr_get_runtime_delegate -> " + Hex(static_cast<unsigned long>(rc)));
        if (rc < 0 || !loader) return false;

        // (wchar_t const*)-1 is UNMANAGEDCALLERSONLY_METHOD: no delegate type, the method
        // is called through its own native signature.
        rc = reinterpret_cast<LoadAssembly>(loader)(
            (dir + L"FortiVpnPlugin.dll").c_str(),
            L"FortiVpnPlugin.Exports, FortiVpnPlugin",
            L"CreateInstance",
            reinterpret_cast<wchar_t const*>(-1),
            nullptr,
            reinterpret_cast<void**>(&g_create));
        Trace(L"load_assembly_and_get_function_pointer -> " + Hex(static_cast<unsigned long>(rc)));
        if (rc < 0) { g_create = nullptr; return false; }

        Trace(L"runtime ready");
        return true;
    }

    struct Factory : IActivationFactory
    {
        LONG refs = 1;

        HRESULT __stdcall QueryInterface(REFIID iid, void** object) noexcept override
        {
            if (iid == __uuidof(IUnknown) || iid == __uuidof(IInspectable) ||
                iid == __uuidof(IActivationFactory))
            {
                *object = static_cast<IActivationFactory*>(this);
                AddRef();
                return S_OK;
            }
            *object = nullptr;
            return E_NOINTERFACE;
        }

        ULONG __stdcall AddRef() noexcept override { return InterlockedIncrement(&refs); }

        ULONG __stdcall Release() noexcept override
        {
            ULONG remaining = InterlockedDecrement(&refs);
            if (remaining == 0) delete this;
            return remaining;
        }

        HRESULT __stdcall GetIids(ULONG* count, IID** iids) noexcept override
        {
            *count = 0;
            *iids = nullptr;
            return S_OK;
        }

        HRESULT __stdcall GetRuntimeClassName(HSTRING* name) noexcept override
        {
            return WindowsCreateString(L"FortiVpnPlugin.FortiPlugin", 26, name);
        }

        HRESULT __stdcall GetTrustLevel(TrustLevel* level) noexcept override
        {
            *level = BaseTrust;
            return S_OK;
        }

        HRESULT __stdcall ActivateInstance(IInspectable** instance) noexcept override
        {
            *instance = nullptr;
            if (!StartRuntime()) return E_FAIL;

            void* created = nullptr;
            int hr = g_create(&created);
            Trace(L"CreateInstance -> " + Hex(static_cast<unsigned long>(hr)));
            if (hr < 0) return hr;

            *instance = static_cast<IInspectable*>(created);
            return S_OK;
        }
    };
}

BOOL __stdcall DllMain(HINSTANCE instance, DWORD reason, void*)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_self = instance;
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}

extern "C" HRESULT __stdcall DllGetActivationFactory(void* classId, void** factory) noexcept
{
    UINT32 length = 0;
    wchar_t const* raw = WindowsGetStringRawBuffer(static_cast<HSTRING>(classId), &length);
    std::wstring const name{ raw ? raw : L"", length };
    Trace(L"DllGetActivationFactory(" + name + L")");

    if (name != L"FortiVpnPlugin.FortiPlugin")
    {
        *factory = nullptr;
        return REGDB_E_CLASSNOTREG;
    }

    // The runtime is started here rather than in ActivateInstance so a hosting failure is
    // reported as a failed class lookup, which is what the caller can actually log.
    if (!StartRuntime())
    {
        *factory = nullptr;
        return E_FAIL;
    }

    *factory = static_cast<IActivationFactory*>(new Factory());
    return S_OK;
}

extern "C" HRESULT __stdcall DllCanUnloadNow()
{
    // The runtime cannot be unloaded, so neither can this.
    return S_FALSE;
}
