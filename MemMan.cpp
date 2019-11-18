#include "MemMan.h"

cMemMan::cMemMan()
{
#ifdef WIN32
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
#endif
}

cMemMan::~cMemMan()
{
#ifdef WIN32
	CloseHandle(hProcess);
#endif
}

bool cMemMan::ReadMemory(const void* lpBaseAddress, const void *lpBuffer, const int _nSize)
{
	bool bResult;

#ifdef WIN32
	bResult = (ReadProcessMemory(hProcess, lpBaseAddress, (LPVOID)lpBuffer, _nSize, NULL) != 0);
#else
	bResult = true;
	
	bResult &= UnProtect(lpBaseAddress, _nSize);

	unsigned int p_size = sysconf(_SC_PAGESIZE);
	char* all_adr = (char*)(((unsigned int)lpBaseAddress) & ~(p_size - 1));
	unsigned int size = (unsigned int)lpBaseAddress - (unsigned int)all_adr + _nSize;

	bResult &= (mlock(all_adr, size) == 0);
	memcpy((void*)lpBuffer, lpBaseAddress, _nSize);
	bResult &= (munlock(all_adr, size) == 0);
#endif
	return bResult;
}

bool cMemMan::WriteMemory(const void* lpBaseAddress, const void *lpBuffer, const int _nSize)
{
	bool bResult;

#ifdef WIN32
	bResult = (WriteProcessMemory(hProcess, (LPVOID)lpBaseAddress, lpBuffer, _nSize, NULL) != false);
#else
	bResult = true;

	bResult &=UnProtect(lpBaseAddress, _nSize);

	unsigned int p_size = sysconf(_SC_PAGESIZE);
	char* all_adr = (char*)(((unsigned int)lpBaseAddress) & ~(p_size - 1));
	unsigned int size = (unsigned int)lpBaseAddress - (unsigned int)all_adr + _nSize;

	bResult &= (mlock(all_adr, size) == 0);
	memcpy((void*)lpBaseAddress, lpBuffer, _nSize);
	bResult &= (munlock(all_adr, size) == 0);
#endif
	return bResult;
}

bool cMemMan::UnProtect(const void*lpBaseAddress, const int _nSize)
{
	bool bResult = false;
#ifdef WIN32
	DWORD oldprv;
	bResult = (VirtualProtect((void*)lpBaseAddress, _nSize, PAGE_EXECUTE_READWRITE, &oldprv) != false);
#else
	unsigned int p_size = sysconf(_SC_PAGESIZE);
	char* all_adr = (char*)(((unsigned int)lpBaseAddress) & ~(p_size - 1));
	unsigned int size = (unsigned int)lpBaseAddress - (unsigned int)all_adr + _nSize;
	bResult = (mprotect(all_adr, size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0);

#endif
	return bResult;
}
