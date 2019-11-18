#ifdef WIN32
#include <winsock2.h>
#define _FPREFIX __stdcall
#else
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#define _FPREFIX
#define SOCKET int
#endif

#include <string>
#include <map>
#include <ctime>
#include "qcache_mm.h"
#include "Detour.h"

#define A2S_INFO_REQUEST		"\xFF\xFF\xFF\xFF\x54"
#define A2S_INFO_REPLY			"\xFF\xFF\xFF\xFF\x49"

QCachePlugin g_QCachePlugin;
QCacheListener g_QCacheListener;
PLUGIN_EXPOSE(QCachePlugin, g_QCachePlugin);

// -- Detours --

cDetour recvfrom_detour;
cDetour sendto_detour;

typedef int(_FPREFIX  *sendto_f)(SOCKET, const char *, int, int, const struct sockaddr *, int);
typedef int(_FPREFIX *recvfrom_f)(SOCKET, char *, int, int, struct sockaddr *, int *);

int _FPREFIX sendto_hook(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
int _FPREFIX recvfrom_hook(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);
int _FPREFIX recvfrom_hook_RM(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);

// -- / Detours --

// -- CVArs --

double CacheDelay = 5.0;
void qc_time_Changed(IConVar *var, const char *pOldValue, float flOldValue);
ConVar qc_time("qc_time", "5", FCVAR_PROTECTED, "A2S_INFO requests timeout in seconds.", true, 0, true, 3600, qc_time_Changed);
void qc_time_Changed(IConVar *var, const char *pOldValue, float flOldValue)
{
	CacheDelay = qc_time.GetFloat();
}

bool bRequestMapEnabled = true;
void qc_requestmap_enabled_Changed(IConVar *var, const char *pOldValue, float flOldValue);
ConVar qc_requestmap_enabled("qc_requestmap_enabled", "1", FCVAR_PROTECTED, "Enables or disables the RequestMap", true, 0, true, 1, qc_requestmap_enabled_Changed);
void qc_requestmap_enabled_Changed(IConVar *var, const char *pOldValue, float flOldValue)
{
	bool bValue = (qc_requestmap_enabled.GetInt() != 0);

	if (bValue == bRequestMapEnabled)
		return;

	bool bOkay = true;

	bOkay &= recvfrom_detour.UnHookFunction();
	META_CONPRINTF("[QCache] UnHooking recvfrom - %s.\n", bOkay ? "SUCCESS" : "FAILED");

	if (!bValue)
	{
		bOkay &= recvfrom_detour.HookFunction((void*)recvfrom, (void*)recvfrom_hook);
		META_CONPRINTF("[QCache] Hooking recvfrom - %s.\n", bOkay ? "SUCCESS" : "FAILED");
		META_CONPRINTF("[QCache] RequestMap disabled.\n");
	}
	else
	{
		bOkay &= recvfrom_detour.HookFunction((void*)recvfrom, (void*)recvfrom_hook_RM);
		META_CONPRINTF("[QCache] Hooking recvfrom - %s.\n", bOkay ? "SUCCESS" : "FAILED");
		META_CONPRINTF("[QCache] RequestMap enabled.\n");
	}

	bRequestMapEnabled = bValue;
}

unsigned int MaxRequests = 3;
void qc_maxrequests_Changed(IConVar *var, const char *pOldValue, float flOldValue);
ConVar qc_maxrequests("qc_maxrequests", "3", FCVAR_PROTECTED, "Maximum ammount of A2S_INFO requests per second.", true, 1, true, 30, qc_maxrequests_Changed);
void qc_maxrequests_Changed(IConVar *var, const char *pOldValue, float flOldValue)
{
	MaxRequests = qc_maxrequests.GetInt();
}

// -- / CVArs --

// -- ConCmds --

void qc_requestmap_Called(const CCommand &command);
ConCommand qc_requestmap("qc_requestmap", qc_requestmap_Called, "Prints the RequestMap.");

void qc_requestmap_clear_Called(const CCommand &command);
ConCommand qc_requestmap_clear("qc_requestmap_clear", qc_requestmap_clear_Called, "Clears the RequestMap.");
// -- / ConCmds --

// -- RequestMap --

struct RMElement
{
	time_t LastRequest;
	unsigned int Requests;
	unsigned int OverLimits;
	RMElement(time_t _LastRequest, unsigned int _Requests, unsigned int _OverLimits) : LastRequest(_LastRequest), Requests(_Requests), OverLimits(_OverLimits) {}
};
std::map<std::string, RMElement> RequestMap;

void qc_requestmap_Called(const CCommand &command)
{
	if (!bRequestMapEnabled)
	{
		META_CONPRINTF("[QCache] RequestMap is disabled.\n");
		return;
	}

	if (RequestMap.empty())
	{
		META_CONPRINTF("[QCache] RequestMap is empty.\n");
		return;
	}

	time_t Now = time(NULL);

	unsigned int tRequests = 0;
	unsigned int tOverLimits = 0;
	unsigned int timeDiff;

	META_CONPRINTF("[QCache] RequestMap contains :\n");
	for (std::map<std::string, RMElement>::iterator it = RequestMap.begin(); it != RequestMap.end(); ++it)
	{
		timeDiff = difftime(Now, it->second.LastRequest);
		META_CONPRINTF("[QCache] IP : % 15s ; LastReq : %u seconds ago ; Requests : %u ; OverLimits : %u\n", it->first.c_str(), timeDiff, it->second.Requests, it->second.OverLimits);
		tRequests += (it->second.Requests * !timeDiff);
		tOverLimits += (it->second.OverLimits * !timeDiff);
	}
	META_CONPRINTF("[QCache] Active traffic : Requests : %u ; Overlimits %u\n", tRequests, tOverLimits);
}

void qc_requestmap_clear_Called(const CCommand &command)
{
	if (!bRequestMapEnabled)
	{
		META_CONPRINTF("[QCache] RequestMap is disabled.\n");
		return;
	}

	RequestMap.clear();

	META_CONPRINTF("[QCache] RequestMap is now empty.\n");
}

// -- / RequestMap --


// -- A2S_INFO Cache --

char *LastBuff;
size_t LastBuffLen;
time_t LastUpdate;

// -- / A2S_INFO Cache --

int _FPREFIX sendto_hook(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen)
{
	sendto_f sendto_Original = (sendto_f)sendto_detour.OriginalPointer();

	if (len > 5)
	{
		if (!memcmp(buf, A2S_INFO_REPLY, 5))
		{
			time_t Now = time(NULL);

			if (difftime(Now, LastUpdate) > CacheDelay)
			{
				//META_CONPRINTF("[QCache] Cached A2S_INFO_REPLY.\n");

				LastUpdate = Now;
				delete[] LastBuff;
				LastBuff = new char[len];
				memcpy(LastBuff, buf, len);
				LastBuffLen = len;
			}
			//META_CONPRINTF("[QCache] Sending A2S_INFO_REPLY.\n");
		}
	}

	int Result = sendto_Original(s, buf, len, flags, to, tolen);

	return Result;
}

int _FPREFIX recvfrom_hook(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen)
{
	recvfrom_f recvfrom_Original = (recvfrom_f)recvfrom_detour.OriginalPointer();
	sendto_f sendto_Original = (sendto_f)sendto_detour.OriginalPointer();

	int Result = recvfrom_Original(s, buf, len, flags, from, fromlen);

	if (Result > 5)
	{
		if (!memcmp(buf, A2S_INFO_REQUEST, 5))
		{
			time_t Now = time(NULL);

			//META_CONPRINTF("[QCache] Received A2S_INFO_REQUEST.\n");

			if (difftime(Now, LastUpdate) < CacheDelay)
			{
				//META_CONPRINTF("[QCache] Sending cached A2S_INFO_REPLY.\n");

				sendto_Original(s, LastBuff, LastBuffLen, 0, from, *fromlen);

				return -1;
			}
		}
	}

	return Result;
}

int _FPREFIX recvfrom_hook_RM(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen)
{
	recvfrom_f recvfrom_Original = (recvfrom_f)recvfrom_detour.OriginalPointer();
	sendto_f sendto_Original = (sendto_f)sendto_detour.OriginalPointer();

	int Result = recvfrom_Original(s, buf, len, flags, from, fromlen);

	if (Result > 5)
	{
		if (!memcmp(buf, A2S_INFO_REQUEST, 5))
		{
			time_t Now = time(NULL);

			//META_CONPRINTF("[QCache] Received A2S_INFO_REQUEST.\n");

			std::string IP(inet_ntoa(((sockaddr_in*)from)->sin_addr));

			std::map<std::string, RMElement>::iterator it = RequestMap.find(IP);
			if (it == RequestMap.end())
				RequestMap.insert(std::pair<std::string, RMElement>(IP, RMElement(Now, 1, 0)));
			else
			{
				if (it->second.LastRequest == Now)
					it->second.Requests++;
				else
				{
					it->second.LastRequest = Now;
					it->second.Requests = 1;
				}

				if (it->second.Requests >= MaxRequests)
				{
					//META_CONPRINTF("[QCache] A2S_INFO request limit per second hit by %s \n",IP.c_str());

					it->second.OverLimits++;

					return -1;
				}

			}

			if (difftime(Now, LastUpdate) < CacheDelay)
			{
				//META_CONPRINTF("[QCache] Sending cached A2S_INFO_REPLY.\n");

				sendto_Original(s, LastBuff, LastBuffLen, 0, from, *fromlen);

				return -1;
			}
		}
	}

	return Result;
}

IServerGameDLL *Server = NULL;
ICvar *iCVar = NULL;

class BaseAccessor : public IConCommandBaseAccessor
{
public:
	bool RegisterConCommandBase(ConCommandBase *pCommandBase)
	{
		return META_REGCVAR(pCommandBase);
	}
} s_BaseAccessor;

bool QCachePlugin::Load(PluginId id, ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
	PLUGIN_SAVEVARS();

	/* Make sure we build on MM:S 1.4 */
#if defined METAMOD_PLAPI_VERSION
	GET_V_IFACE_ANY(GetServerFactory, Server, IServerGameDLL, INTERFACEVERSION_SERVERGAMEDLL);
#else
	GET_V_IFACE_ANY(serverFactory, Server, IServerGameDLL, INTERFACEVERSION_SERVERGAMEDLL);
#endif

#if SOURCE_ENGINE >= SE_ORANGEBOX
	GET_V_IFACE_CURRENT(GetEngineFactory, iCVar, ICvar, CVAR_INTERFACE_VERSION);
	g_pCVar = iCVar;
	ConVar_Register(0, &s_BaseAccessor);
#else
	ConCommandBaseMgr::OneTimeInit(&s_BaseAccessor);
#endif

	ismm->AddListener(g_PLAPI, &g_QCacheListener);

	bool bOkay = true;
	bOkay &= recvfrom_detour.HookFunction((void*)recvfrom, (void*)recvfrom_hook_RM);
	META_CONPRINTF("[QCache] Hooking recvfrom - %s.\n", bOkay ? "SUCCESS" : "FAILED");
	bOkay &= sendto_detour.HookFunction((void*)sendto, (void*)sendto_hook);
	META_CONPRINTF("[QCache] Hooking sendto - %s.\n", bOkay ? "SUCCESS" : "FAILED");

	RequestMap.clear();

	return bOkay;
}

void QCacheListener::OnLevelInit(char const *pMapName, char const *pMapEntities, char const *pOldLevel, char const *pLandmarkName, bool loadGame, bool background)
{
	RequestMap.clear();
}

bool QCachePlugin::Unload(char *error, size_t maxlen)
{
	bool bOkay = true;
	bOkay &=recvfrom_detour.UnHookFunction();
	META_CONPRINTF("[QCache] UnHooking recvfrom - %s.\n", bOkay ? "SUCCESS" : "FAILED");
	bOkay &=sendto_detour.UnHookFunction();
	META_CONPRINTF("[QCache] UnHooking sendto - %s.\n", bOkay ? "SUCCESS" : "FAILED");
	
	RequestMap.clear();

	return bOkay;
}

void QCachePlugin::AllPluginsLoaded()
{
	/* This is where we'd do stuff that relies on the mod or other plugins
	 * being initialized (for example, cvars added and events registered).
	 */
}

bool QCachePlugin::Pause(char *error, size_t maxlen)
{
	return true;
}

bool QCachePlugin::Unpause(char *error, size_t maxlen)
{
	return true;
}

const char *QCachePlugin::GetLicense()
{
	return "Public Domain";
}

const char *QCachePlugin::GetVersion()
{
	return "1.0.0.1";
}

const char *QCachePlugin::GetDate()
{
	return __DATE__;
}

const char *QCachePlugin::GetLogTag()
{
	return "QCACHE";
}

const char *QCachePlugin::GetAuthor()
{
	return "Hashira";
}

const char *QCachePlugin::GetDescription()
{
	return "Cache system for A2S_INFO replies. Original author recon0,ivailosp.";
}

const char *QCachePlugin::GetName()
{
	return "Query Cache 2";
}

const char *QCachePlugin::GetURL()
{
	return "http://www.sourcemm.net/";
}
