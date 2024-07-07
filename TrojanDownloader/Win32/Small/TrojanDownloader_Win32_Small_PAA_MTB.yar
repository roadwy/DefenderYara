
rule TrojanDownloader_Win32_Small_PAA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Small.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 57 69 6e 53 79 73 4e 65 74 77 6f 72 6b } //1 SYSTEM\CurrentControlSet\Services\WinSysNetwork
		$a_01_1 = {5c 5c 2e 5c 50 48 59 53 49 43 41 4c 44 52 49 56 45 } //1 \\.\PHYSICALDRIVE
		$a_01_2 = {5c 6c 6f 63 61 6c 73 6f 61 73 2e 64 61 74 } //1 \localsoas.dat
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_4 = {77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 } //1 winlogon.exe
		$a_01_5 = {48 4f 53 54 20 56 61 6c 75 65 } //1 HOST Value
		$a_01_6 = {44 4e 53 20 56 61 6c 75 65 } //1 DNS Value
		$a_01_7 = {49 50 20 56 61 6c 75 65 } //1 IP Value
		$a_01_8 = {53 79 73 53 63 6e 65 74 } //1 SysScnet
		$a_01_9 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_10 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
		$a_01_11 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //1 Process32First
		$a_01_12 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //1 Process32Next
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}