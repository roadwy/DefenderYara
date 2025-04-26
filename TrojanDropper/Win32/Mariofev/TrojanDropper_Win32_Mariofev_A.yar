
rule TrojanDropper_Win32_Mariofev_A{
	meta:
		description = "TrojanDropper:Win32/Mariofev.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0c 00 07 00 00 "
		
	strings :
		$a_00_0 = {00 20 70 20 49 20 6e 20 69 20 74 20 5f 20 44 20 6c 20 6c 20 73 00 } //8
		$a_00_1 = {64 6c 6c 63 61 63 68 65 5c 75 73 65 72 33 32 2e 64 6c 6c } //2 dllcache\user32.dll
		$a_02_2 = {57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 [0-10] 41 70 70 49 6e 69 74 5f 44 6c 6c 73 00 } //2
		$a_01_3 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 NtQuerySystemInformation
		$a_01_4 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_01_5 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //1 FindResourceA
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_00_0  & 1)*8+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=12
 
}