// One file that installs the whole product. The package layout rides inside this
// executable as a resource, so there is nothing to unpack by hand and nothing to
// download, and every step it takes is a per-user one: no administrator anywhere.
//
// It does what install.ps1 does, in the same order and for the same reasons -- stop
// whatever is holding the files, drop the old registration, replace the folder, register
// the layout again -- but without needing PowerShell or an execution policy to be argued
// with first.
//
// Two things here look like details and are not:
//
//   * The static CRT (/MT). An installer that needs a VC++ redistributable installed
//     before it can install anything is no use to somebody without an administrator.
//   * FortiVpnSetup.manifest. Windows applies installer-detection heuristics to any
//     unmanifested executable with "setup" in its name and asks for elevation -- the one
//     thing this whole package exists to avoid. An embedded asInvoker manifest turns the
//     heuristic off.

#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <string>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Management.Deployment.h>

namespace
{
    using namespace winrt;
    using namespace winrt::Windows::Management::Deployment;

    // Both come from Package.appxmanifest and must keep matching it: they are how an
    // already-installed copy is found again in order to be replaced.
    constexpr wchar_t PackageName[] = L"FortiGateSslVpn.Plugin";
    constexpr wchar_t PackagePublisher[] = L"CN=FortiVpnPluginDev";
    constexpr wchar_t ProviderName[] = L"VPNTunnelWiS";
    constexpr wchar_t FolderName[] = L"FortiVpnMatrix";

    void Say(std::wstring const& line) { wprintf(L"%s\n", line.c_str()); }

    std::wstring Environment(wchar_t const* name)
    {
        wchar_t value[MAX_PATH]{};
        DWORD length = GetEnvironmentVariableW(name, value, MAX_PATH);
        return (length == 0 || length >= MAX_PATH) ? std::wstring{} : std::wstring{ value };
    }

    // Read, not written: this is the one prerequisite, and checking it costs nothing while
    // failing to check it produces a deployment error nobody can act on.
    bool DeveloperModeOn()
    {
        DWORD value = 0;
        DWORD size = sizeof(value);
        LSTATUS status = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock",
            L"AllowDevelopmentWithoutDevLicense",
            RRF_RT_REG_DWORD, nullptr, &value, &size);
        return status == ERROR_SUCCESS && value == 1;
    }

    bool WritePayload(std::wstring const& path)
    {
        HRSRC const found = FindResourceW(nullptr, L"PAYLOAD", RT_RCDATA);
        if (!found) return false;

        HGLOBAL const loaded = LoadResource(nullptr, found);
        DWORD const size = SizeofResource(nullptr, found);
        void const* const bytes = loaded ? LockResource(loaded) : nullptr;
        if (!bytes || size == 0) return false;

        HANDLE const file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;

        DWORD written = 0;
        BOOL const ok = WriteFile(file, bytes, size, &written, nullptr);
        CloseHandle(file);
        return ok && written == size;
    }

    bool Run(std::wstring commandLine)
    {
        STARTUPINFOW startup{ sizeof(startup) };
        PROCESS_INFORMATION process{};

        // CreateProcessW may write to its command line, so it gets a buffer it is allowed
        // to modify rather than a string literal.
        if (!CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process))
            return false;

        WaitForSingleObject(process.hProcess, INFINITE);
        DWORD code = 1;
        GetExitCodeProcess(process.hProcess, &code);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return code == 0;
    }

    // A registered package locks its own DLLs, and the host is the process holding them.
    // Any live tunnel goes down with it -- it is being served by the files about to be
    // replaced, so there is no version of this that leaves the connection up.
    void StopHost()
    {
        HANDLE const snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W entry{ sizeof(entry) };
        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (_wcsicmp(entry.szExeFile, L"FortiVpnHost.exe") != 0) continue;

                HANDLE const process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE,
                                                   entry.th32ProcessID);
                if (!process) continue;
                TerminateProcess(process, 0);
                WaitForSingleObject(process, 5000);
                CloseHandle(process);
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    void RemoveTree(std::wstring const& dir)
    {
        WIN32_FIND_DATAW found{};
        HANDLE const search = FindFirstFileW((dir + L"\\*").c_str(), &found);
        if (search == INVALID_HANDLE_VALUE) return;

        do
        {
            std::wstring const name{ found.cFileName };
            if (name == L"." || name == L"..") continue;

            std::wstring const child = dir + L"\\" + name;
            if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                RemoveTree(child);
            }
            else
            {
                // The publish output carries read-only files; DeleteFileW refuses those.
                SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(child.c_str());
            }
        } while (FindNextFileW(search, &found));

        FindClose(search);
        RemoveDirectoryW(dir.c_str());
    }

    void RemoveRegistration(PackageManager const& manager)
    {
        for (auto const& package : manager.FindPackagesForUser({}, PackageName, PackagePublisher))
        {
            Say(L"Removing the previous registration...");
            auto const result = manager.RemovePackageAsync(package.Id().FullName(),
                                                           RemovalOptions::None).get();
            if (!result.ErrorText().empty())
                Say(L"  " + std::wstring{ result.ErrorText() });
        }
    }

    // DevelopmentMode is the whole point: it is what lets an unsigned loose folder be
    // registered by an ordinary user. A signed .msix would instead need its certificate in
    // LocalMachine\Root, which needs an administrator.
    bool RegisterLayout(PackageManager const& manager, std::wstring const& installDir)
    {
        std::wstring path = installDir + L"\\AppxManifest.xml";
        for (auto& c : path) if (c == L'\\') c = L'/';

        Windows::Foundation::Uri const uri{ L"file:///" + path };
        auto const result = manager.RegisterPackageAsync(uri, nullptr,
                                                         DeploymentOptions::DevelopmentMode).get();
        if (result.ErrorText().empty()) return true;

        Say(L"Registering the package failed: " + std::wstring{ result.ErrorText() });
        return false;
    }

    int Uninstall(PackageManager const& manager, std::wstring const& installDir)
    {
        StopHost();
        RemoveRegistration(manager);
        RemoveTree(installDir);
        Say(L"Removed. Connections you created are left alone; delete them in Settings.");
        return 0;
    }

    int Install(PackageManager const& manager, std::wstring const& installDir)
    {
        std::wstring const payload = Environment(L"TEMP") + L"\\FortiVpnSetup-payload.zip";

        Say(L"Unpacking...");
        if (!WritePayload(payload))
        {
            Say(L"The bundled package could not be written to " + payload);
            return 1;
        }

        StopHost();
        RemoveRegistration(manager);
        RemoveTree(installDir);
        if (!CreateDirectoryW(installDir.c_str(), nullptr) &&
            GetLastError() != ERROR_ALREADY_EXISTS)
        {
            Say(L"Could not create " + installDir);
            DeleteFileW(payload.c_str());
            return 1;
        }

        // tar.exe has shipped in System32 since Windows 10 1803 and reads zip archives, so
        // the alternative -- carrying a decompressor -- buys nothing. The package requires
        // 10.0.19041 anyway, well past the version that introduced it.
        bool const unpacked = Run(L"\"" + Environment(L"SystemRoot") + L"\\System32\\tar.exe\""
                                  L" -xf \"" + payload + L"\" -C \"" + installDir + L"\"");
        DeleteFileW(payload.c_str());
        if (!unpacked)
        {
            Say(L"Unpacking into " + installDir + L" failed.");
            return 1;
        }

        Say(L"Registering...");
        if (!RegisterLayout(manager, installDir)) return 1;

        Say(L"");
        Say(L"Done. Settings > Network & internet > VPN > Add VPN,");
        Say(std::wstring{ L"set VPN provider = \"" } + ProviderName + L"\", enter your gateway address");
        Say(L"including the port (for example vpn.example.com:10443) and Save.");
        return 0;
    }
}

int wmain(int argc, wchar_t** argv)
{
    init_apartment();

    // The installed folder is read by the registered package for as long as it stays
    // registered, so it is a real location under LOCALAPPDATA and never a temp folder.
    std::wstring const local = Environment(L"LOCALAPPDATA");
    if (local.empty())
    {
        Say(L"LOCALAPPDATA is not set; there is nowhere to install to.");
        return 1;
    }
    std::wstring const installDir = local + L"\\" + FolderName;

    bool const remove = argc > 1 && (_wcsicmp(argv[1], L"/remove") == 0 ||
                                     _wcsicmp(argv[1], L"/uninstall") == 0);

    int code = 1;
    try
    {
        PackageManager const manager;

        if (remove)
        {
            code = Uninstall(manager, installDir);
        }
        else if (!DeveloperModeOn())
        {
            Say(L"Developer Mode must be on before installing:");
            Say(L"  Settings > System > For developers > Developer Mode = On");
            Say(L"");
            Say(L"Windows only registers an unsigned package with it enabled. Turning it on");
            Say(L"does not need an administrator.");
        }
        else
        {
            code = Install(manager, installDir);
        }
    }
    catch (hresult_error const& ex)
    {
        Say(L"Unexpected error: " + std::wstring{ ex.message() });
    }

    // Double-clicked, this is the only process on its console and the window would close
    // on the last line before anyone read it. Launched from a shell, it must not block.
    DWORD owners[2]{};
    if (GetConsoleProcessList(owners, 2) == 1)
    {
        wprintf(L"\nPress Enter to close.");
        (void)getwchar();
    }

    return code;
}
