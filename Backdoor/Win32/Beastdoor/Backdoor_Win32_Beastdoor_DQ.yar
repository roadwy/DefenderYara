
rule Backdoor_Win32_Beastdoor_DQ{
	meta:
		description = "Backdoor:Win32/Beastdoor.DQ,SIGNATURE_TYPE_PEHSTR_EXT,ffffff96 00 ffffff96 00 08 00 00 "
		
	strings :
		$a_01_0 = {42 65 61 73 74 79 } //100 Beasty
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_01_2 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 Toolhelp32ReadProcessMemory
		$a_00_3 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //10 Process32First
		$a_01_4 = {6e 73 31 2e 69 70 2d 70 6c 75 73 2e 6e 65 74 } //5 ns1.ip-plus.net
		$a_01_5 = {47 65 74 53 63 72 65 65 6e } //5 GetScreen
		$a_01_6 = {47 65 74 57 65 62 43 61 6d } //5 GetWebCam
		$a_01_7 = {53 68 75 74 20 44 6f 77 6e 3a 5b } //5 Shut Down:[
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_00_3  & 1)*10+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5) >=150
 
}