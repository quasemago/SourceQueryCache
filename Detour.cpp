#include "Detour.h"

cDetour::cDetour() : OrigFunc(NULL), RealFunc(NULL), nSize(0)
{
}

cDetour::~cDetour()
{
	UnHookFunction();
	delete(char*) OrigFunc;
}

int cDetour::FindOffset(void *Func, int MinOffset)
{
	_DecodeResult res;
	_DecodedInst decodedInstructions[100];
	_DecodeType dt = Decode32Bits;
	_OffsetType offset = 0;

	unsigned int decodedInstructionsCount = 0;
	int InstrSize = 0;

	res = distorm_decode(offset, (const unsigned char*)Func, 64, dt, decodedInstructions, sizeof(decodedInstructions) / sizeof(_DecodedInst), &decodedInstructionsCount);
	if (res == DECRES_INPUTERR)
		return -1;

	for (unsigned int i = 0; i < decodedInstructionsCount; ++i)
	{
		if (InstrSize >= MinOffset)
			break;
		InstrSize += decodedInstructions[i].size;
	}

	if (InstrSize < MinOffset)
		return -1;
	else
		return InstrSize;
}

static const char *__JMP = "\x68\x00\x00\x00\x00\xC3";
#define __JMP_Size 6

bool cDetour::HookFunction(void *_OrigFunc, void *_FakeFunc)
{
	if (OrigFunc)
	{
		delete(char*) OrigFunc;
		OrigFunc = NULL;
	}

	bool bResult = true;

	int SizeNeeded = FindOffset(_OrigFunc, __JMP_Size);
	if (SizeNeeded < 0)
		return false;

	RealFunc = _OrigFunc;
	char MakeJMP[__JMP_Size];
	memcpy(MakeJMP, __JMP, __JMP_Size);
	unsigned int FakeOffset = (unsigned int)_FakeFunc;
	memcpy(MakeJMP + 1, (void*)&FakeOffset, sizeof(FakeOffset));

	OrigFunc = (void*)new char[SizeNeeded + __JMP_Size];

	bResult &= MemMan.ReadMemory(_OrigFunc, OrigFunc, SizeNeeded);

	memcpy((char*)OrigFunc + SizeNeeded, __JMP, __JMP_Size);
	unsigned int OrigOffset = (unsigned int)_OrigFunc + SizeNeeded;
	memcpy((char*)OrigFunc + SizeNeeded + 1, (void*)&OrigOffset, sizeof(OrigOffset));

	nSize = SizeNeeded;

	bResult &= MemMan.WriteMemory(_OrigFunc, MakeJMP, __JMP_Size);
	bResult &= MemMan.UnProtect(OrigFunc, SizeNeeded + __JMP_Size);

	return bResult;
}

bool cDetour::UnHookFunction()
{
	if (!OrigFunc || !RealFunc)
		return false;

	return MemMan.WriteMemory(RealFunc, OrigFunc, __JMP_Size);
}

void* cDetour::OriginalPointer()
{
	return OrigFunc;
}