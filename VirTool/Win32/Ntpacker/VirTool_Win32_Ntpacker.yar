
rule VirTool_Win32_Ntpacker{
	meta:
		description = "VirTool:Win32/Ntpacker,SIGNATURE_TYPE_PEHSTR_EXT,34 08 08 07 0c 00 00 ffffffe8 03 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 95 98 fe ff ff 33 c0 e8 90 01 04 8b 85 90 01 02 ff ff e8 90 01 04 50 e8 90 01 04 8b f0 6a 00 6a 00 6a 00 56 90 00 } //64 00 
		$a_00_1 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //64 00  ZwUnmapViewOfSection
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //64 00  WriteProcessMemory
		$a_01_3 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //64 00  CreateRemoteThread
		$a_01_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //64 00  CreateToolhelp32Snapshot
		$a_00_5 = {48 54 54 50 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 5c } //64 00  HTTP\shell\open\command\
		$a_00_6 = {73 68 65 6c 6c 5f 74 72 61 79 77 6e 64 } //64 00  shell_traywnd
		$a_00_7 = {73 76 63 68 6f 73 74 2e 65 78 65 } //64 00  svchost.exe
		$a_00_8 = {4f 70 65 6e 54 68 72 65 61 64 } //64 00  OpenThread
		$a_00_9 = {77 69 6e 64 69 72 } //64 00  windir
		$a_00_10 = {47 65 74 57 69 6e 64 6f 77 54 68 72 65 61 64 50 72 6f 63 65 73 73 49 64 } //64 00  GetWindowThreadProcessId
		$a_01_11 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  ReadProcessMemory
	condition:
		any of ($a_*)
 
}