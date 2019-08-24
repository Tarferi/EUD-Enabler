#include <Windows.h>
#include <cstdint>

#define EUD_CONDITIONS_PTR 0x00515A98
#define EUD_ACTIONS_PTR 0x00512800

#define EUD_CURRENT_PLAYER 0x006509B0
#define EUD_DEATHS 0x0058A364

#define COND_DEATHS 15
#define ACT_SET_DEATHS 45

#define ADDR_COND_DEATHS (EUD_CONDITIONS_PTR + (4 * COND_DEATHS))
#define ADDR_ACT_SET_DEATHS (EUD_ACTIONS_PTR + (4 * ACT_SET_DEATHS))

#define CURRENT_PLAYER 13

#define AT_LEAST 0
#define AT_MOST 1
#define SET_TO 7
#define ADD 8
#define SUBTRACT 9
#define EXACTLY 10

#define ADDR_READFILE 0x004FE3FC

typedef int32_t int32;
typedef uint32_t uint32;
typedef uint16_t uint16;
typedef uint8_t uint8;

typedef uint32(__fastcall *actF)(void*);
typedef uint32(__fastcall *condF)(void*);

typedef bool(__stdcall *SFileReadFileF)(HANDLE hFile, LPVOID lpBuffer, DWORD dwToRead, DWORD * pdwRead, LPVOID lpOverlapped);

struct ActionData {
	uint32 SourceLocation;
	uint32 TriggerText;
	uint32 WAVStringNumber;
	uint32 Time;
	uint32 Player;
	uint32 Group;
	uint16 UnitType;
	uint8 ActionType;
	uint8 UnitsNumber;
	uint8 flags;
	uint8 Unused[3];
};

struct ConditionData {
	uint32 locationNumber;
	uint32 groupNumber;
	uint32 Quantifier;
	uint16 UnitID;
	uint8 Comparision;
	uint8 ConditionType;
	uint8 Resource;
	uint8 flags;
	uint16 Unused;

};

static actF originalAction;
static condF originalCondition;
static SFileReadFileF originalReadFile;

uint32 __fastcall eud_cond(ConditionData* condition) {
	if (condition->ConditionType == COND_DEATHS) {
		uint32 playerID = condition->groupNumber;
		uint32 unitID = condition->UnitID;
		uint32 comparator = condition->Comparision;
		uint32 condValue = condition->Quantifier;
		uint32 mask = condition->locationNumber;

		mask = (condition->Unused & 0xFF) == 'S' && condition->Unused >> 8 == 'C' ? mask : 0xFFFFFFFF;

		if (playerID == CURRENT_PLAYER) {
			playerID = *((uint32*)EUD_CURRENT_PLAYER);
		}
		uint32 offset = EUD_DEATHS + (((unitID * 12) + playerID) * 4);
		uint32 value = *((uint32*)offset);

		value &= mask;
		if (comparator == AT_LEAST) {
			return value >= condValue;
		} else if (comparator == AT_MOST) {
			return value <= condValue;
		} else if (comparator == EXACTLY) {
			return value == condValue;
		}
	}
	return originalCondition(condition);
}

uint32 __fastcall eud_act(ActionData* action) {
	if (action->ActionType == ACT_SET_DEATHS) {
		uint32 playerID = action->Player;
		uint32 unitID = action->UnitType;
		uint32 number = action->Group;
		uint32 modifier = action->UnitsNumber;
		uint32 mask = action->SourceLocation;

		uint8 UnusedPtr[2] = { action->Unused[1], action->Unused[2] };

		mask = UnusedPtr[0] == (uint8) 'S' && UnusedPtr[1] == (uint8) 'C' ? mask : 0xFFFFFFFF;


		if (playerID == CURRENT_PLAYER) {
			playerID = *((uint32*)EUD_CURRENT_PLAYER);
		}
		uint32 offset = EUD_DEATHS + (((unitID * 12) + playerID) * 4);
		uint32 nextValue = *((uint32*)offset);
		uint32 originalValue = nextValue & (~mask);
		if (modifier == SET_TO) {
			nextValue = number;
		} else if (modifier == ADD) {
			nextValue += number;
		} else if (modifier == SUBTRACT) {
			nextValue -= number;
		}
		nextValue =  originalValue | (nextValue & mask);
		*((uint32*)offset) = nextValue;
	}
	return true;
}

static const char* SECTIONS[] = { "TYPE", "VER ", "IVER", "IVE2", "VCOD", "IOWN", "OWNR", "ERA ", "DIM ", "SIDE", "MTXM", "PUNI", "UPGR", "PTEC", "UNIT", "ISOM", "TILE", "DD2 ", "THG2", "MASK", "STR ", "UPRP", "UPUS", "MRGN", "TRIG", "MBRF", "SPRP", "FORC", "WAV ", "UNIS", "UPGS", "TECS", "SWNM", "COLR", "PUPx", "PTEx", "UNIx", "UPGx", "TECx" };

void patchFile(uint8* data, int32 length) {
	unsigned char* ptr = (unsigned char*) data;
	while (length > 8) {
		uint8 sectionName[5] = { 0, 0, 0, 0, 0 };
		memcpy(sectionName, ptr, 4);
		ptr += 4;
		length -= 4;
		int32 sectionLength = *((int32*)ptr);
		ptr += 4;
		length -= 4;
		if (length >= sectionLength) {
			if (!memcmp(sectionName, "VER ", 4)) {
				uint16* typePtr = (uint16*)ptr;
				if ((*typePtr) == 206 || (*typePtr) == 60 || (*typePtr) == 64) {
					*typePtr = (*typePtr) - 1;
				}
				ptr += 2;
			} else {
				length -= sectionLength;
			}
		} else {
			return;
		}
	}
}

bool __stdcall SFileReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD dwToRead, DWORD * pdwRead, LPVOID lpOverlapped) {
	if (originalReadFile(hFile, lpBuffer, dwToRead, pdwRead, lpOverlapped)) {
		if(pdwRead != nullptr){
			DWORD read = *pdwRead;
			if (read > 4) { // Could verify CHK
				uint8 sectionName[5] = { 0, 0, 0, 0, 0 };
				memcpy(sectionName, lpBuffer, 4);
				for (uint32 i = 0; i < sizeof(SECTIONS) / sizeof(char*); i++) {
					if (!memcmp(SECTIONS[i], sectionName, 4)) { // Possible CHK, Patch
						patchFile((uint8*)lpBuffer, read);
						return true;
					}
				}
			}
		}
		return true;
	}
	return false;
}

bool attach() {
	DWORD previousProtection;
	if (!VirtualProtect((LPVOID)ADDR_READFILE, 4, PAGE_EXECUTE_READWRITE, &previousProtection)) {
		return false;
	}

	originalReadFile = (SFileReadFileF) *((uint32*)ADDR_READFILE);
	originalCondition = (condF) *((uint32*)ADDR_COND_DEATHS);
	originalAction = (actF) *((uint32*)ADDR_ACT_SET_DEATHS);

	*((uint32*)ADDR_READFILE) = (uint32)&SFileReadFile;
	*((uint32*)ADDR_COND_DEATHS) = (uint32)&eud_cond;
	*((uint32*)ADDR_ACT_SET_DEATHS) = (uint32)&eud_act;
	return true;
}

void detach() {
	*((int32*)ADDR_READFILE) = (int32)originalReadFile;
	*((int32*)ADDR_COND_DEATHS) = (int32)originalCondition;
	*((int32*)ADDR_ACT_SET_DEATHS) = (int32)originalAction;
}

#ifdef BUILD_CHAOS_PLUGIN
const char szName[] = "Starcraft_EUDEnablerLibrary";
char dllPath[1024];
HANDLE hMapFile;

struct AttachmentStruct {
	DWORD pid;
};

BOOL openSharedMemory(AttachmentStruct* str, bool write) {
	const int BUF_SIZE = 512;
	if (hMapFile == NULL) {
		hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, szName);
		if (hMapFile == NULL) { // First ?
			hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, BUF_SIZE, szName);
			if (hMapFile == NULL) {
				return FALSE;
			}
		}
	}
	LPCTSTR pBuf = (LPTSTR)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, BUF_SIZE);
	if (pBuf == NULL) {
		CloseHandle(hMapFile);
		hMapFile = NULL;
		return FALSE;
	}
	if (write) {
		CopyMemory((PVOID)pBuf, str, sizeof(AttachmentStruct));
	} else {
		CopyMemory(str, (PVOID)pBuf, sizeof(AttachmentStruct));
	}
	UnmapViewOfFile(pBuf);

	return TRUE;
}

void closeSharedMemory() {
	if (hMapFile != NULL) {
		CloseHandle(hMapFile);
	}
	hMapFile = NULL;
}

bool isInSc() {
	AttachmentStruct str;
	if (openSharedMemory(&str, false)) {
		if (str.pid == GetCurrentProcessId()) {
			return true;
		}
	}
	return false;
}

#endif

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
#ifdef BUILD_CHAOS_PLUGIN
		memset(dllPath, 0, sizeof(dllPath));
		GetModuleFileNameA(hModule, dllPath, sizeof(dllPath));
		hMapFile = NULL;
		if (isInSc()) {
#endif
			attach();
#ifdef BUILD_CHAOS_PLUGIN
		}
#endif
	} else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
#ifdef BUILD_CHAOS_PLUGIN
		if (isInSc()) {
#endif
			detach();
#ifdef BUILD_CHAOS_PLUGIN
		}
		closeSharedMemory();
#endif
	}
	return TRUE;
}

#ifdef BUILD_CHAOS_PLUGIN

#define BWLAPI 4
#define STARCRAFTBUILD 13

struct ExchangeData {
	int32 iPluginAPI;
	int32 iStarCraftBuild;
	BOOL bNotSCBWmodule;
	BOOL bConfigDialog;
};

extern "C" __declspec(dllexport) void GetPluginAPI(ExchangeData &Data) {
	Data.iPluginAPI = BWLAPI;
	Data.iStarCraftBuild = STARCRAFTBUILD;
	Data.bConfigDialog = false;
	Data.bNotSCBWmodule = true;
}

extern "C" __declspec(dllexport) void GetData(char *name, char *description, char *updateurl) {
#define strcpy(src, str) memcpy(src, str, strlen(str)+1)
	strcpy(name, "Extended EUD Enabler");
	strcpy(description, "EUD Enabler by Tarferi\r\n\r\nThis plugin replaces default death conditions and death actions with custom functions that support remastered stuff");
	strcpy(updateurl, "http://rion.cz/epd/eudnabler/update");
}

extern "C" __declspec(dllexport) BOOL OpenConfig() {
	return true;
}

extern "C" __declspec(dllexport) bool ApplyPatchSuspended(HANDLE hProcess, DWORD dwProcessID) {
	return true;
}

extern "C" __declspec(dllexport) bool ApplyPatch(HANDLE hProcess, DWORD dwProcessID) {

	long dll_size = strlen(dllPath) + 1;
	LPVOID MyAlloc = VirtualAllocEx(hProcess, NULL, dll_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (MyAlloc == NULL) {
		return false;
	}

	int IsWriteOK = WriteProcessMemory(hProcess, MyAlloc, dllPath, dll_size, 0);
	if (IsWriteOK == 0 || IsWriteOK == ERROR_INVALID_HANDLE) {
		return false;
	}

	AttachmentStruct str;
	str.pid = dwProcessID;
	if (!openSharedMemory(&str, true)) {
		return false;
	}

	DWORD dWord;
	LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibraryA("kernel32"), "LoadLibraryA");
	HANDLE ThreadReturn = CreateRemoteThread(hProcess, NULL, 0, addrLoadLibrary, MyAlloc, 0, &dWord);
	if (ThreadReturn == NULL) {
		return false;
	}

	return true;
}

#endif