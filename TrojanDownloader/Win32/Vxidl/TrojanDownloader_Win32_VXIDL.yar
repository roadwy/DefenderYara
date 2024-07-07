
rule TrojanDownloader_Win32_VXIDL{
	meta:
		description = "TrojanDownloader:Win32/VXIDL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 64 00 6f 00 67 00 2e 00 73 00 79 00 73 00 00 00 00 00 7a 00 63 00 6c 00 69 00 65 00 6e } //1
		$a_01_1 = {61 00 76 00 73 00 73 00 2e 00 65 00 78 00 65 00 00 00 6b 00 61 00 76 00 73 00 76 00 63 00 2e 00 } //1
		$a_00_2 = {0f 20 c0 50 25 ff ff fe ff 0f 22 c0 } //1
		$a_01_3 = {00 00 8b 55 10 66 81 3a 4d 5a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_Win32_VXIDL_2{
	meta:
		description = "TrojanDownloader:Win32/VXIDL,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_00_0 = {26 69 64 3d 00 00 00 00 25 75 00 00 63 3a 00 00 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 00 00 00 00 25 64 00 00 43 3a 5c } //4
		$a_02_1 = {64 6c 6c 00 53 8b 1d 90 01 04 56 57 8b 7c 24 10 57 33 f6 ff d3 85 c0 7e 0c 80 04 3e 90 01 01 57 46 ff d3 3b f0 7c f4 5f 5e 5b c2 04 00 55 8b ec 81 90 00 } //4
		$a_00_2 = {8d bd 40 fe ff ff f3 ab 8d 45 f8 50 8d 85 40 fe ff ff 50 be 00 01 00 00 53 89 75 f8 e8 } //4
		$a_02_3 = {bf 00 04 00 00 83 7d f8 05 0f 8d 90 01 01 00 00 00 53 68 80 00 00 00 6a 04 53 6a 02 68 00 00 00 40 ff 32 90 00 } //4
		$a_02_4 = {00 00 00 7d 01 40 83 c0 90 01 01 3d 90 01 01 00 00 00 7c 90 00 } //3
		$a_00_5 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_01_6 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
	condition:
		((#a_00_0  & 1)*4+(#a_02_1  & 1)*4+(#a_00_2  & 1)*4+(#a_02_3  & 1)*4+(#a_02_4  & 1)*3+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=13
 
}