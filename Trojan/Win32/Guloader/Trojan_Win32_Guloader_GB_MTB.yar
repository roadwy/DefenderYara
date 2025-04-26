
rule Trojan_Win32_Guloader_GB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 53 74 72 69 6e 67 57 } //1 GetPrivateProfileStringW
		$a_01_1 = {57 72 69 74 65 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 53 74 72 69 6e 67 57 } //1 WritePrivateProfileStringW
		$a_01_2 = {53 65 74 44 65 66 61 75 6c 74 44 6c 6c 44 69 72 65 63 74 6f 72 69 65 73 } //1 SetDefaultDllDirectories
		$a_00_3 = {53 00 65 00 53 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 50 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 } //2 SeShutdownPrivilege
		$a_00_4 = {5c 00 54 00 65 00 6d 00 70 00 } //1 \Temp
		$a_00_5 = {61 00 6e 00 64 00 65 00 62 00 72 00 79 00 73 00 74 00 20 00 72 00 65 00 6e 00 65 00 67 00 6c 00 65 00 63 00 74 00 2e 00 65 00 78 00 65 00 } //4 andebryst reneglect.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*4) >=8
 
}