#ifndef _QC_MEMMAN_H
#define _QC_MEMMAN_H

#include <cstring>

#ifdef WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

class cMemMan
{
private:
#ifdef WIN32
	HANDLE hProcess;
#endif
public:
	cMemMan();
	~cMemMan();
	bool ReadMemory(const void*, const void *, const int);
	bool WriteMemory(const void*, const void *, const int);
	bool UnProtect(const void*, const int);
};

#endif