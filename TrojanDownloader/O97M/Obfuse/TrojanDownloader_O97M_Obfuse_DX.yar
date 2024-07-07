
rule TrojanDownloader_O97M_Obfuse_DX{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DX,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 90 02 10 29 90 00 } //2
		$a_03_1 = {2c 20 4e 75 6c 6c 2c 20 90 02 10 2c 90 00 } //1
		$a_03_2 = {2e 43 72 65 61 74 65 90 01 01 20 5f 90 00 } //1
		$a_01_3 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 = GetObject("winmgmts:Win32_Process")
		$a_03_4 = {2e 43 72 65 61 74 65 90 01 01 20 90 02 10 2c 20 4e 75 6c 6c 2c 20 90 02 10 2c 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}