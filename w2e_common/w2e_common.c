/*****************************************************************//**
 * \file   w2e_common.c
 * \brief  Static library - Common W2E includes, macros and functions
 * 
 * \author ark
 * \date   August 2024
 *********************************************************************/


#include "w2e_common.h"


HANDLE w2e_common__init(char* filter, UINT64 flags)
{
	LPTSTR errormessage = NULL;
	DWORD errorcode = 0;

	w2e_log_printf("Init...\n");

	filter = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, flags);

	if (filter != INVALID_HANDLE_VALUE)
	{
		w2e_log_printf("Init OK\n");
		return filter;
	}

	errorcode = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorcode, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR)&errormessage, 0, NULL);

	w2e_print_error("Error opening filter: %d %s\n", errorcode, errormessage);

	LocalFree(errormessage);

	if (errorcode == 2)
	{
		w2e_print_error("The driver files WinDivert32.sys or WinDivert64.sys were not found.\n");
	}
	else if (errorcode == 654)
	{
		w2e_print_error(
			"An incompatible version of the WinDivert driver is currently loaded.\n"
			"Please unload it with the following commands ran as administrator:\n\n"
			"sc stop windivert\n"
			"sc delete windivert\n"
			"sc stop windivert14"
			"sc delete windivert14\n");
	}
	else if (errorcode == 1275)
	{
		w2e_print_error(
			"This error occurs for various reasons, including:\n"
			"the WinDivert driver is blocked by security software; or\n"
			"you are using a virtualization environment that does not support drivers.\n");
	}
	else if (errorcode == 1753)
	{
		w2e_print_error(
			"This error occurs when the Base Filtering Engine service has been disabled.\n"
			"Enable Base Filtering Engine service.\n");
	}
	else if (errorcode == 577)
	{
		w2e_print_error(
			"Could not load driver due to invalid digital signature.\n"
			"Windows Server 2016 systems must have secure boot disabled to be \n"
			"able to load WinDivert driver.\n"
			"Windows 7 systems must be up-to-date or at least have KB3033929 installed.\n"
			"https://www.microsoft.com/en-us/download/details.aspx?id=46078\n\n"
			"WARNING! If you see this error on Windows 7, it means your system is horribly "
			"outdated and SHOULD NOT BE USED TO ACCESS THE INTERNET!\n"
			"Most probably, you don't have security patches installed and anyone in you LAN or "
			"public Wi-Fi network can get full access to your computer (MS17-010 and others).\n"
			"You should install updates IMMEDIATELY.\n");
	}

	return NULL;
}

static int __w2e_common__deinit(HANDLE handle)
{
	if (handle)
	{
		WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
		WinDivertClose(handle);
		return TRUE;
	}
	return FALSE;
}

void w2e_common__deinit_all(HANDLE* filters, int filter_num)
{
	w2e_log_printf("Deinitialize...\n");
	for (int i = 0; i < filter_num; i++)
	{
		__w2e_common__deinit(filters[i]);
	}
}