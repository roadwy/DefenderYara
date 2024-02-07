
rule Trojan_Win32_Delf_BB{
	meta:
		description = "Trojan:Win32/Delf.BB,SIGNATURE_TYPE_PEHSTR_EXT,61 01 5f 01 20 00 00 64 00 "
		
	strings :
		$a_00_0 = {53 65 72 76 69 63 65 44 6c 6c 2e 64 6c 6c } //64 00  ServiceDll.dll
		$a_00_1 = {53 65 72 76 69 63 65 4d 61 69 6e } //64 00  ServiceMain
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //14 00  WriteProcessMemory
		$a_00_3 = {44 45 4c 53 65 72 } //0f 00  DELSer
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0f 00  URLDownloadToFileA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //0a 00  InternetReadFile
		$a_00_6 = {53 57 5a 32 30 30 36 } //0a 00  SWZ2006
		$a_00_7 = {57 4a 44 32 30 30 36 } //0a 00  WJD2006
		$a_00_8 = {6e 65 65 64 20 64 69 63 74 69 6f 6e 61 72 79 } //01 00  need dictionary
		$a_00_9 = {46 69 6e 64 45 78 65 63 75 74 61 62 6c 65 41 } //01 00  FindExecutableA
		$a_00_10 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //01 00  AdjustTokenPrivileges
		$a_00_11 = {46 74 70 47 65 74 46 69 6c 65 41 } //01 00  FtpGetFileA
		$a_00_12 = {46 74 70 50 75 74 46 69 6c 65 41 } //01 00  FtpPutFileA
		$a_00_13 = {47 65 74 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 49 6e 66 6f } //01 00  GetProcessMemoryInfo
		$a_00_14 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //01 00  InternetConnectA
		$a_01_15 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //01 00  InternetOpenA
		$a_00_16 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 41 } //01 00  LookupPrivilegeValueA
		$a_00_17 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //01 00  OpenSCManagerA
		$a_00_18 = {4f 70 65 6e 53 65 72 76 69 63 65 41 } //01 00  OpenServiceA
		$a_00_19 = {51 75 65 72 79 53 65 72 76 69 63 65 53 74 61 74 75 73 } //01 00  QueryServiceStatus
		$a_01_20 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 43 74 72 6c 48 61 6e 64 6c 65 72 41 } //01 00  RegisterServiceCtrlHandlerA
		$a_00_21 = {52 65 6d 6f 76 65 44 69 72 65 63 74 6f 72 79 41 } //01 00  RemoveDirectoryA
		$a_00_22 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  ShellExecuteA
		$a_00_23 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //01 00  ShellExecuteExA
		$a_00_24 = {73 6f 63 6b 65 74 } //01 00  socket
		$a_00_25 = {53 74 61 72 74 53 65 72 76 69 63 65 41 } //01 00  StartServiceA
		$a_00_26 = {57 69 6e 45 78 65 63 } //01 00  WinExec
		$a_00_27 = {54 52 65 67 69 73 74 72 79 53 } //05 00  TRegistryS
		$a_00_28 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 44 72 69 76 65 72 73 33 32 5c } //05 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32\
		$a_00_29 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c } //01 00  Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\
		$a_00_30 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 } //01 00  %SystemRoot%
		$a_00_31 = {53 65 52 65 73 74 6f 72 65 50 72 69 76 69 6c 65 67 65 } //00 00  SeRestorePrivilege
	condition:
		any of ($a_*)
 
}