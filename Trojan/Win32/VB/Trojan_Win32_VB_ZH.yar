
rule Trojan_Win32_VB_ZH{
	meta:
		description = "Trojan:Win32/VB.ZH,SIGNATURE_TYPE_PEHSTR_EXT,3e 00 3e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //5 MSVBVM60.DLL
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //5 CreateToolhelp32Snapshot
		$a_00_2 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //5 Process32First
		$a_00_3 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //5 Process32Next
		$a_00_4 = {46 69 6e 64 57 69 6e 64 6f 77 45 78 41 } //5 FindWindowExA
		$a_00_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //5 ShellExecuteA
		$a_01_6 = {73 00 6d 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //5 smhost.exe
		$a_01_7 = {73 00 65 00 72 00 76 00 6c 00 6f 00 67 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //5 servlogon.exe
		$a_01_8 = {5c 00 49 00 50 00 43 00 24 00 } //5 \IPC$
		$a_01_9 = {5c 00 41 00 44 00 4d 00 49 00 4e 00 24 00 } //5 \ADMIN$
		$a_01_10 = {53 00 68 00 6f 00 77 00 50 00 6f 00 70 00 75 00 70 00 73 00 } //5 ShowPopups
		$a_01_11 = {78 00 78 00 78 00 78 00 2e 00 63 00 6f 00 6d 00 } //3 xxxx.com
		$a_01_12 = {31 00 37 00 74 00 61 00 68 00 75 00 6e 00 2e 00 63 00 6f 00 6d 00 } //3 17tahun.com
		$a_01_13 = {5c 00 43 00 79 00 72 00 61 00 78 00 2e 00 76 00 62 00 70 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*5+(#a_00_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5+(#a_01_10  & 1)*5+(#a_01_11  & 1)*3+(#a_01_12  & 1)*3+(#a_01_13  & 1)*1) >=62
 
}