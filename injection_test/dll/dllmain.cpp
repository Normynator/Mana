// PING ----------------------------------------------------------------
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>
#include <Ws2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
// PING ----------------------------------------------------------------

#include <Windows.h>
#include <iostream>
#include <future>

#include "detours.h"
#include "sigscan.h"
#include <sstream>



DWORD chat_hist_func = 0;
DWORD print_message_func = 0;
DWORD current_object_func = 0;

// OLD
void chat_hist_hook()
{
	DWORD* chat_ptr = 0;

	__asm
	{
		push eax
		xor eax, eax
		add eax, DWORD PTR[ecx + 0x70]
		add chat_ptr, eax
		pop eax
	}

	char* msg = (char*)(*chat_ptr);
	MessageBox(0, msg, "MessageBox caption", MB_OK);

	// leave
	__asm
	{
		mov esp, ebp
		pop ebp
		xor eax, eax
		add eax, 0x00A8EC64

		// orginal instr ---
		push esi
		push edi
		push 0xFFFF00FF
		// -----------------

		push 0x004C188D
		ret
	}

	//DWORD st_entry = chat_ptr + 0x70;
}

int SHOW_HDC_ADDR = 1;
int SHOW_ERROR = 1;
int test_count = 0;

// template for orginal function
typedef void (__thiscall *chat_hist)(HDC hdc_obj);
typedef HDC(__thiscall *current_object)(HDC hdc_hdl, int a2);
typedef void (__thiscall *print_message)(HDC hdc_obj, int x, int y, LPCSTR message, size_t m_len,
	int a6, int a7, COLORREF color, int a9);


// PING ----------------------------------------------------------------
HANDLE hIcmpFile;
unsigned long ipaddr = INADDR_NONE;
DWORD dwRetVal = 0;
char SendData[32] = "Data Buffer";
LPVOID ReplyBuffer = NULL;
DWORD ReplySize = 0;
PCSTR strAddr = "158.69.48.156";
int PING_ERROR = 0;
HDC hdc_obj_for_ping;
LPCSTR ping_m = "NaN";
std::thread ping_thr;
bool end_thr = false;
// PING ----------------------------------------------------------------

void __fastcall ping_inject() {
	while (true) {
		ping_m = "NaN";
		if (!PING_ERROR) {
			dwRetVal = IcmpSendEcho(hIcmpFile, ipaddr, SendData, sizeof(SendData),
				NULL, ReplyBuffer, ReplySize, 1000);
			if (dwRetVal != 0) {
				PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
				struct in_addr ReplyAddr;
				ULONG ping = pEchoReply->RoundTripTime;
				char buffer[16];
				sprintf_s(buffer, "%d ms", ping);
				ping_m = buffer;
			}
			else {
				PING_ERROR = 1;
			}
		}
		if (end_thr)
			break;
		Sleep(200);
	}
}

void __fastcall chat_hist_hook2(HDC hdc_obj)
{
	if (SHOW_HDC_ADDR) {
		char buffer[256];
		BYTE* chat_addr = (BYTE*)hdc_obj + 0x70; // Byte is probably wrong type here!
		char* first_entry = (char*)*((DWORD*)*((DWORD*)chat_addr));
		sprintf_s(buffer, "First message from chat history: %s", first_entry);
		MessageBox(0, buffer, "MessageBox caption", MB_OK);
		SHOW_HDC_ADDR = 0;

		// PING
		hdc_obj_for_ping = hdc_obj;
		InetPton(AF_INET, strAddr, &ipaddr);

		hIcmpFile = IcmpCreateFile();
		if (hIcmpFile == INVALID_HANDLE_VALUE) {
			PING_ERROR = 1;
		}

		ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
		ReplyBuffer = (VOID*)malloc(ReplySize);
		if (ReplyBuffer == NULL) {
			PING_ERROR = 1;
		}
		ping_thr = std::thread(ping_inject);
		// PING
	}
	/* Bit of playing arround!
	HDC hdc_hdl = 0;
	__asm {
		lea ecx, DWORD PTR[ebp-0x2C]
		mov hdc_hdl, ecx
	}

	current_object original_current_obj = (current_object)current_object_func;
	original_current_obj(hdc_hdl, *((DWORD *)hdc_obj + 6));

	int point = 10;
	HFONT hFont = CreateFont(point * GetDeviceCaps(hdc_obj, LOGPIXELSY) / 72,
		0, 0, 0, FW_NORMAL, TRUE, FALSE, FALSE,
		ANSI_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
		ANTIALIASED_QUALITY, VARIABLE_PITCH, "Times New Roman");
	//SetTextAlign(*hdc_obj, TA_BASELINE | TA_LEFT);

	SetTextColor(hdc_obj, RGB(178, 34, 34));
	SelectObject(hdc_obj, hFont);
	

	LPCWSTR message2 = L"Test text!!";
	bool result = TextOutW(hdc_obj, 0, 30, message2, wcslen(message2));
	if (!result && SHOW_ERROR) {
		MessageBox(0, "Error!", "MessageBox caption", MB_OK);
		SHOW_ERROR = 0;
	}
	*/

	chat_hist original_chat_hist = (chat_hist)chat_hist_func;
	original_chat_hist(hdc_obj);

	// PING
	print_message original_print_message = (print_message)print_message_func;
	if (!PING_ERROR)
		original_print_message(hdc_obj_for_ping, 460, 3, ping_m, strlen(ping_m), 0, 12, RGB(178, 34, 34), 0);
	else {
		LPCSTR message = "Ping error!";
		original_print_message(hdc_obj, 460, 3, message, strlen(message), 0, 12, RGB(178, 34, 34), 0);
	}
	// PING
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	// store the address of sum() in testprogram.exe here.
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		//chat_hist_func = 0x004C1886;
		chat_hist_func = 0x004C1880;
		print_message_func = 0x005D5870;
		//chat_hist_func = 0x005B3EA0;
		current_object_func = 0x0040E3D0;

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// this will hook the function
		DetourAttach(&(LPVOID&)chat_hist_func, &chat_hist_hook2);

		DetourTransactionCommit();
		//MessageBox(0, "DLL injected!!", "MessageBox caption", MB_OK);
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		end_thr = true;
		ping_thr.join();
		// unhook
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// this will hook the function
		DetourDetach(&(LPVOID&)chat_hist_func, &chat_hist_hook2);

		DetourTransactionCommit();
	}
	//MessageBox(0, "Finished injection try!", "MessageBox caption", MB_OK);
	return TRUE;
}