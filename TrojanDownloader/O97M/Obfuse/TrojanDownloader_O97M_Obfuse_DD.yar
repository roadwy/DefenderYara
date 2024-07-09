
rule TrojanDownloader_O97M_Obfuse_DD{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DD,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 GetObject("winmgmts:Win32_Process")
		$a_02_2 = {2e 43 72 65 61 74 65 20 [0-30] 20 2b 20 [0-40] 2c 20 4e 75 6c 6c 2c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_DD_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DD,SIGNATURE_TYPE_MACROHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 = GetObject("winmgmts:Win32_Process")
		$a_02_2 = {53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 90 10 07 00 20 2d 20 90 10 07 00 } //10
		$a_02_3 = {43 72 65 61 74 65 20 [0-20] 20 2b 20 [0-20] 20 2b 20 [0-20] 20 2b 20 [0-30] 2c 20 4e 75 6c 6c 2c 20 [0-10] 2c 20 70 72 6f 63 65 73 73 69 64 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*10+(#a_02_3  & 1)*10) >=22
 
}