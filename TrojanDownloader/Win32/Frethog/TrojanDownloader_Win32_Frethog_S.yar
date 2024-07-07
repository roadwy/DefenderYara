
rule TrojanDownloader_Win32_Frethog_S{
	meta:
		description = "TrojanDownloader:Win32/Frethog.S,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
		$a_01_1 = {41 63 63 65 70 74 3a } //1 Accept:
		$a_00_2 = {41 67 65 6e 74 25 6c 64 } //1 Agent%ld
		$a_00_3 = {41 63 63 65 70 74 3a 20 2a 2f 2a } //1 Accept: */*
		$a_01_4 = {53 65 74 44 49 50 53 48 6f 6f 6b } //4 SetDIPSHook
		$a_01_5 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //1 GetSystemDirectoryA
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*4+(#a_01_5  & 1)*1) >=9
 
}