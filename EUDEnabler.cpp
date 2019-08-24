#include <Windows.h>

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

typedef int(__fastcall *actF)(void*);
typedef int(__fastcall *condF)(void*);

struct ActionData {
	unsigned int SourceLocation;
	unsigned int TriggerText;
	unsigned int WAVStringNumber;
	unsigned int Time;
	unsigned int Player;
	unsigned int Group;
	unsigned short UnitType;
	unsigned char ActionType;
	unsigned char UnitsNumber;
	unsigned char flags;
	unsigned char Unused[3];
};

struct ConditionData {
	unsigned int locationNumber;
	unsigned int groupNumber;
	unsigned int Quantifier;
	unsigned short UnitID;
	unsigned char Comparision;
	unsigned char ConditionType;
	unsigned char Resource;
	unsigned char flags;
	unsigned short Unused;

};

static actF originalAction;
static condF originalCondition;

int __fastcall eud_cond(ConditionData* condition) {
	if (condition->ConditionType == COND_DEATHS) {
		unsigned int playerID = condition->groupNumber;
		unsigned int unitID = condition->UnitID;
		unsigned int comparator = condition->Comparision;
		unsigned int condValue = condition->Quantifier;

		if (playerID == CURRENT_PLAYER) {
			playerID = *((unsigned int*)EUD_CURRENT_PLAYER);
		}
		unsigned int offset = EUD_DEATHS + (((unitID * 12) + playerID) * 4);
		unsigned int value = *((unsigned int*)offset);
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

int __fastcall eud_act(ActionData* action) {
	if (action->ActionType == ACT_SET_DEATHS) {
		unsigned int playerID = action->Player;
		unsigned int unitID = action->UnitType;
		unsigned int number = action->Group;
		unsigned int modifier = action->UnitsNumber;

		if (playerID == CURRENT_PLAYER) {
			playerID = *((unsigned int*)EUD_CURRENT_PLAYER);
		}
		unsigned int offset = EUD_DEATHS + (((unitID * 12) + playerID) * 4);
		if (modifier == SET_TO) {
			*((unsigned int*)offset) = number;
		} else if (modifier == ADD) {
			unsigned int currentValue = *((unsigned int*)offset);
			currentValue += number;
			*((unsigned int*)offset) = currentValue;
		} else if (modifier == SUBTRACT) {
			unsigned int currentValue = *((unsigned int*)offset);
			currentValue -= number;
			*((unsigned int*)offset) = currentValue;
		}
	}
	return originalAction(action);
}

void attach() {
	originalCondition = (condF) *((unsigned int*)ADDR_COND_DEATHS);
	originalAction = (actF) *((unsigned int*)ADDR_ACT_SET_DEATHS);
	*((unsigned int*)ADDR_COND_DEATHS) = (unsigned int)&eud_cond;
	*((unsigned int*)ADDR_ACT_SET_DEATHS) = (unsigned int)&eud_act;
}

void detach() {
	*((unsigned int*)ADDR_COND_DEATHS) = (unsigned int)originalCondition;
	*((unsigned int*)ADDR_ACT_SET_DEATHS) = (unsigned int)originalAction;
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
	int iPluginAPI;
	int iStarCraftBuild;
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