
rule PWS_Win32_Wowsteal_V{
	meta:
		description = "PWS:Win32/Wowsteal.V,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //1 Accept-Language: zh-cn
		$a_00_1 = {69 66 20 65 78 69 73 74 } //1 if exist
		$a_00_2 = {57 6f 72 6c 64 20 6f 66 20 57 61 72 63 72 61 66 74 } //1 World of Warcraft
		$a_00_3 = {57 4f 57 2e 45 58 45 } //1 WOW.EXE
		$a_00_4 = {47 78 57 69 6e 64 6f 77 43 6c 61 73 73 44 33 64 } //1 GxWindowClassD3d
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion
		$a_01_6 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}