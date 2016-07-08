#include <iostream>
#include <string>
#include <sstream>
#include <windows.h>
#include <Lm.h>
#include <vector>

using namespace std;

#define NETINFO_DEBUG 1

void PutIntoWCharBuf(const std::wstring& str, std::vector<wchar_t>& outbuf)
{
	for(size_t i=0; i<str.length(); i++)
		outbuf.push_back(str[i]);
}

void PutIntoWCharBuf(int num, std::vector<wchar_t>& outbuf)
{
	std::wstring numStr = L"";

	::wstringstream wss;
	wss << num;
	wss >> numStr;

	PutIntoWCharBuf(numStr, outbuf);
}

void PrintOutputHeader(std::vector<wchar_t>& outbuf)
{
	wcout << "<netinfo>\n";
	PutIntoWCharBuf(L"<netinfo>", outbuf);
}

void PrintOutputFooter(std::vector<wchar_t>& outbuf)
{
	wcout << "</netinfo>\n";
	PutIntoWCharBuf(L"</netinfo>", outbuf);
}

void GetShareInfo(std::vector<wchar_t>& outbuf, const std::wstring& sharePathFull)
{
	std::wstring serverName = L"";
	std::wstring shareName = L"";

	int backslashCount = 0;
	for(size_t i=0; i<sharePathFull.length(); i++)
	{
		if(sharePathFull[i] == '\\')
		{
			backslashCount++;

			if(backslashCount == 3) // start of share name, skip this backslash
				continue;
		}

		if(backslashCount >= 3) // we're reading the share name
		{
			shareName += sharePathFull[i];
		}
		else // we're reading the server name
		{
			serverName += sharePathFull[i];
		}
	}

	PSHARE_INFO_502		BufPtr;
	NET_API_STATUS		res;
	res = NetShareGetInfo( 0 /* execute on local PC */, (wchar_t*)shareName.c_str(), 502, (LPBYTE*) &BufPtr);
	
	if(res == ERROR_ACCESS_DENIED) 
	{
		wcout << "<security>access_denied</security>\n";
		PutIntoWCharBuf(L"<security>access_denied</security>", outbuf);
	}
	else if(res == NERR_NetNameNotFound) {
		wcout << "<security>not_found</security>\n";
		PutIntoWCharBuf(L"<security>not_found</security>", outbuf);
	}
	else if(res == NERR_Success)
	{
		bool hasSecurity = false;
		bool bCanRead = false;
		bool bCanWrite = false;
		bool bCanDelete = false;

		if(BufPtr->shi502_security_descriptor != NULL)
		{
			BOOL daclPresent = 0;
			PACL dacl = 0;
			BOOL daclDefaulted = 0;

			GetSecurityDescriptorDacl(BufPtr->shi502_security_descriptor, &daclPresent, &dacl, &daclDefaulted);

			if(!daclPresent)
				return; // no access
			else
			{
				if(dacl == NULL)
				{
					// full permission
					hasSecurity = true;
				}
				else
				{
					for(int i=0; i<(int)dacl->AceCount; i++)
					{

						bCanRead = false;
						bCanWrite = false;
						bCanDelete = false;

						PACE_HEADER ace = 0;
						GetAce(dacl, i, (LPVOID*)&ace); 

						if(ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
						{
							PACCESS_ALLOWED_ACE aceAllow = (PACCESS_ALLOWED_ACE)ace;
							//GetAce(dacl, i, (LPVOID*)&aceAllow); 

							PSID sid = (PSID)&aceAllow->SidStart;

							PSID sidEverybody = 0;
							SID_IDENTIFIER_AUTHORITY authWorld = SECURITY_WORLD_SID_AUTHORITY;
							BOOL allocWorldSidOK = AllocateAndInitializeSid(&authWorld, 1, SECURITY_WORLD_RID,	0, 0, 0, 0,	0, 0, 0, &sidEverybody);

							if(!allocWorldSidOK)
								continue;

							BOOL sidOk = EqualSid(sid, sidEverybody);

							FreeSid(sidEverybody);

							if(!sidOk)
								continue;


							bool bGenericAll = ((aceAllow->Mask & GENERIC_ALL) != 0); // win2000 sees this differently than the individual read,write,del masks below

							if(bGenericAll) 
							{
								bCanRead = true;
								bCanWrite = true;
								bCanDelete = true;
							} 
							else 
							{

								if ((aceAllow->Mask & 0x1F01FF) == 0x1F01FF)
								{
									// Console.WriteLine("Permission: Full Control");
										bCanRead = true;
										bCanWrite = true;
								}
								else if ((aceAllow->Mask & 0x1301BF) == 0x1301BF)
								{
									// Console.WriteLine("Permission: READ and CHANGE");
										bCanRead = true;
										bCanWrite = true;
								}
								else if ((aceAllow->Mask & 0x1200A9) == 0x1200A9)
								{
									//Console.WriteLine("Permission: READ only");

										bCanRead = true;
										//bCanWrite = true;
								} else {
								}

					/*			bCanRead = ((aceAllow->Mask & FILE_GENERIC_READ) == 0);
								bCanWrite = ((aceAllow->Mask & FILE_GENERIC_WRITE) == 0);
								bCanDelete = ((aceAllow->Mask & DELETE) == 0);*/
							}


							if(bGenericAll || (bCanRead && bCanWrite && bCanDelete))
							{
								// ok
								hasSecurity = true;
								break;
							}
							else
							{
								bCanRead = false;
								bCanWrite = false;
								bCanDelete = false;
								continue;
							}
						}
						else
						{
							continue; // no access
						}
					}
				}				
			}
		}

		if(hasSecurity)
		{
			wcout << "<security>access_granted</security>\n";
			PutIntoWCharBuf(L"<security>access_granted</security>", outbuf);

			if(bCanRead) {
				wcout << "<security_read>true</security_read>\n";
				PutIntoWCharBuf(L"<security_read>true</security_read>", outbuf);
			} else {
				wcout << "<security_read>false</security_read>\n";
				PutIntoWCharBuf(L"<security_read>false</security_read>", outbuf);
			}

			if(bCanWrite) {
				wcout << "<security_write>true</security_write>\n";
				PutIntoWCharBuf(L"<security_write>true</security_write>", outbuf);
			} else {
				wcout << "<security_write>false</security_write>\n";
				PutIntoWCharBuf(L"<security_write>false</security_write>", outbuf);
			}

			if(bCanDelete) {
				wcout << "<security_delete>true</security_delete>\n";
				PutIntoWCharBuf(L"<security_delete>true</security_delete>", outbuf);
			} else {
				wcout << "<security_delete>false</security_delete>\n";
				PutIntoWCharBuf(L"<security_delete>false</security_delete>", outbuf);
			}

			wcout << "<max_users>" << (int)(BufPtr->shi502_max_uses) << "</max_users>\n";
			PutIntoWCharBuf(L"<max_users>", outbuf);
			PutIntoWCharBuf((int)(BufPtr->shi502_max_uses), outbuf);
			PutIntoWCharBuf(L"</max_users>", outbuf);

			std::wstring localPath( (wchar_t*)BufPtr->shi502_path ); 
			wcout << "<local_path>" << localPath << "</local_path>\n";
			PutIntoWCharBuf(L"<local_path>", outbuf);
			PutIntoWCharBuf(localPath, outbuf);
			PutIntoWCharBuf(L"</local_path>", outbuf);

		}
		else
		{
			wcout << "<security>no_acl</security>\n";
			PutIntoWCharBuf(L"<security>no_acl</security>", outbuf);
		}

		NetApiBufferFree(BufPtr);
	}
	else {
	}
}

void PrintNetResource(std::vector<wchar_t>& outbuf, NETRESOURCE* res)
{
	wcout << "<resource>\n";
	PutIntoWCharBuf(L"<resource>", outbuf);

	std::wstring resStr = (std::wstring)(res->lpRemoteName);
	wcout << "<name>" << resStr << "</name>\n";
	PutIntoWCharBuf(L"<name>", outbuf);
	PutIntoWCharBuf(resStr, outbuf);
	PutIntoWCharBuf(L"</name>", outbuf);

	GetShareInfo(outbuf, resStr);

	wcout << "</resource>\n";
	PutIntoWCharBuf(L"</resource>", outbuf);
}


void EnumLocalResources(std::vector<wchar_t>& outbuf)
{
	PSHARE_INFO_502 BufPtr;
	DWORD numEntries = 0;
	DWORD totalEntries = 0;
	NetShareEnum(NULL, 502, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &numEntries, &totalEntries, NULL);

	for(DWORD i=0; i<numEntries; i++) 
	{
		SHARE_INFO_502 sh = BufPtr[i];

		// PrintNetResource(outbuf, BufPtr[i].shi502_path);
	}
}

void EnumNetResources(std::vector<wchar_t>& outbuf, NETRESOURCE* container=NULL)
{
	HANDLE	enumHandle;
	DWORD ret = WNetOpenEnum(RESOURCE_GLOBALNET, RESOURCETYPE_DISK, 0, container, &enumHandle);



	if(ret == ERROR_EXTENDED_ERROR) 
	{

		DWORD dwWNetResult, dwLastError; 
		WCHAR szError[256]; 
		WCHAR szCaption[256]; 
		WCHAR szDescription[256]; 
		WCHAR szProvider[256]; 

        dwWNetResult = WNetGetLastError(&dwLastError, // error code
            (LPWSTR) szDescription,  // buffer for error description 
            sizeof(szDescription),  // size of error buffer
            (LPWSTR)szProvider,     // buffer for provider name 
            sizeof(szProvider));    // size of name buffer


		wcout << szError;
		wcout << "\n";

	}
	else if(ret == ERROR_NO_NETWORK) {
		wcout << "ERROR_NO_NETWORK\n";
	}
	else if(ret == NO_ERROR)
	{
		DWORD numEntries = -1;
		NETRESOURCE* netRes = new NETRESOURCE[256];
		DWORD bufferSize = sizeof(NETRESOURCE)*256;
		ret = WNetEnumResource(enumHandle, &numEntries, netRes, &bufferSize);

		for(DWORD i=0; i<numEntries; i++)
		{
			if((netRes[i].dwUsage & RESOURCEUSAGE_CONTAINER) == RESOURCEUSAGE_CONTAINER)
				EnumNetResources(outbuf, &netRes[i]);
			else
			{
				PrintNetResource(outbuf, &netRes[i]);
			}
		}

		WNetCloseEnum(enumHandle);

		delete [] netRes;
	}
	else
	{ 
	}


}

void main(int argc, char **argv)
{
	std::vector<wchar_t> outbuf;

	if(!NETINFO_DEBUG)
	{
		if(argc != 3)
			return;

		std::string argstr = argv[1];
		std::string outfile = argv[2];

		if(argstr == "enum_resources")
		{
			PrintOutputHeader(outbuf);
			EnumNetResources(outbuf);
			PrintOutputFooter(outbuf);
		}

		FILE* fp = fopen(outfile.c_str(), "wb");

		for(size_t i=0; i<outbuf.size(); i++)
		{
			fwrite( &outbuf[i], sizeof(wchar_t), 1, fp);
		}

		fclose(fp);

	}
	else
	{
		PrintOutputHeader(outbuf);
		EnumNetResources(outbuf);
		PrintOutputFooter(outbuf);

		std::cout << "\ndone.\n";
		getchar();
	}
}