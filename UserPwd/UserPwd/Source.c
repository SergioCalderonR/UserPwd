#include <Windows.h>
#include <wchar.h>
#include <LM.h>

#pragma comment(lib, "netapi32.lib")

int wmain(int argc, WCHAR * argv[])
{

	DWORD index, admIndex;
	LPWSTR adminName=NULL;

	//NetUserEnum
	NET_API_STATUS localUsers;
	LPCWSTR serverName = NULL;	//Local machine
	DWORD infoLevel = 0;		//USER_INFO_0
	DWORD accountFilter = FILTER_NORMAL_ACCOUNT;
	LPUSER_INFO_0 usersArray=NULL;
	LPUSER_INFO_0 userArrayTemp;
	DWORD prefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD entriesRead=0;
	DWORD totalEntries=0;
	DWORD resumeHandle=0;

	//NetUserSetInfo
	NET_API_STATUS userInfo;
	DWORD level = 1003;	//USER_INFO_1
	USER_INFO_1003 usrArrayOfInfo;
	DWORD parErr;

	if (argc != 2)
	{
		fwprintf(stderr, L"\nUsage: %s [NewPassword]\n", argv[0]);
		return FALSE;
	}
	

	localUsers = NetUserEnum(serverName, infoLevel, accountFilter,
							(LPBYTE*)&usersArray, prefMaxLen, &entriesRead,
							&totalEntries, &resumeHandle);

	userArrayTemp = usersArray;

	if (localUsers != NERR_Success)
	{
		fwprintf(stderr, L"\nError code: %lu\n", localUsers);
		return FALSE;
	}
	else
	{
		for (index = 0; index < entriesRead; index++, userArrayTemp++)
		{
			/*wprintf(L"%s, ", userArrayTemp->usri0_name);*/

			if ((_wcsicmp(userArrayTemp->usri0_name, L"Administrator") == 0) ||
				(_wcsicmp(userArrayTemp->usri0_name, L"Administrador") == 0))
			{
				admIndex = index;
				adminName = userArrayTemp->usri0_name;

			}			
		}

		//Here's the new password
		usrArrayOfInfo.usri1003_password = argv[1];		

		userInfo = NetUserSetInfo(serverName, adminName,
								level, (LPBYTE)&usrArrayOfInfo, &parErr);

		if (userInfo != NERR_Success)
		{
			fwprintf(stderr, L"\nError setting user info, code: %lu\n", userInfo);
			return FALSE;
		}
		else
		{
			wprintf(L"\nUser password has been changed.\n");
		}
	}

	if (NetApiBufferFree(usersArray) != NERR_Success)
	{
		fwprintf(stderr, L"Array buffer could not be freed, code: %lu\n", GetLastError());
		return FALSE;
	}

	usersArray = NULL;

	/*wprintf(L"\nAdmin is in index: %lu\n", admIndex);*/

	return 0;
}