
rule HackTool_Win32_TinyNetInfo_A{
	meta:
		description = "HackTool:Win32/TinyNetInfo.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {36 64 35 61 39 35 64 61 2d 30 66 66 65 2d 34 33 30 33 2d 62 62 32 63 2d 33 39 65 31 38 32 33 33 35 61 39 66 } //1 6d5a95da-0ffe-4303-bb2c-39e182335a9f
		$a_00_1 = {55 00 32 00 56 00 6a 00 64 00 58 00 4a 00 6c 00 55 00 47 00 46 00 7a 00 63 00 33 00 64 00 76 00 63 00 6d 00 51 00 3d 00 } //1 U2VjdXJlUGFzc3dvcmQ=
		$a_01_2 = {43 72 79 70 74 69 6f 6e } //1 Cryption
		$a_01_3 = {47 65 74 44 69 73 6b 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 GetDiskInformation
		$a_00_4 = {49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 64 00 6c 00 6c 00 } //1 Information.dll
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}