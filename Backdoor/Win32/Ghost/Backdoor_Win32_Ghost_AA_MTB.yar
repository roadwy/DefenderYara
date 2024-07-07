
rule Backdoor_Win32_Ghost_AA_MTB{
	meta:
		description = "Backdoor:Win32/Ghost.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 } //1 Process32Next
		$a_01_1 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //1 Process32First
		$a_01_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_3 = {33 36 30 74 72 61 79 } //1 360tray
		$a_01_4 = {45 53 45 54 } //1 ESET
		$a_01_5 = {5c 47 48 4f 53 54 42 41 4b 2e 65 78 65 } //1 \GHOSTBAK.exe
		$a_01_6 = {5c 74 65 6d 70 5c 32 30 31 31 2e 65 78 65 } //1 \temp\2011.exe
		$a_01_7 = {5c 74 65 6d 70 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 \temp\svchost.exe
		$a_01_8 = {33 33 38 39 2e 62 61 74 } //1 3389.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}