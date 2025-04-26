
rule VirTool_Win32_Ntpacker{
	meta:
		description = "VirTool:Win32/Ntpacker,SIGNATURE_TYPE_PEHSTR_EXT,34 08 08 07 0c 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 95 98 fe ff ff 33 c0 e8 ?? ?? ?? ?? 8b 85 ?? ?? ff ff e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b f0 6a 00 6a 00 6a 00 56 } //1000
		$a_00_1 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //100 ZwUnmapViewOfSection
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //100 WriteProcessMemory
		$a_01_3 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //100 CreateRemoteThread
		$a_01_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //100 CreateToolhelp32Snapshot
		$a_00_5 = {48 54 54 50 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 5c } //100 HTTP\shell\open\command\
		$a_00_6 = {73 68 65 6c 6c 5f 74 72 61 79 77 6e 64 } //100 shell_traywnd
		$a_00_7 = {73 76 63 68 6f 73 74 2e 65 78 65 } //100 svchost.exe
		$a_00_8 = {4f 70 65 6e 54 68 72 65 61 64 } //100 OpenThread
		$a_00_9 = {77 69 6e 64 69 72 } //100 windir
		$a_00_10 = {47 65 74 57 69 6e 64 6f 77 54 68 72 65 61 64 50 72 6f 63 65 73 73 49 64 } //100 GetWindowThreadProcessId
		$a_01_11 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //100 ReadProcessMemory
	condition:
		((#a_02_0  & 1)*1000+(#a_00_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100+(#a_00_5  & 1)*100+(#a_00_6  & 1)*100+(#a_00_7  & 1)*100+(#a_00_8  & 1)*100+(#a_00_9  & 1)*100+(#a_00_10  & 1)*100+(#a_01_11  & 1)*100) >=1800
 
}