#ifndef _QC_DETOUR_H
#define _QC_DETOUR_H

#include <cstring>

#include "MemMan.h"
#include "distorm.h"

class cDetour
{
private:
	cMemMan MemMan;

	void* OrigFunc;
	void* RealFunc;
	unsigned int nSize;
	int FindOffset(void *, int);
public:
	cDetour();
	~cDetour();
	bool HookFunction(void *, void *);
	bool UnHookFunction();
	void *OriginalPointer();
};

#endif