
rule TrojanDownloader_O97M_Obfuse_DY{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DY,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 49 6e 6c 69 6e 65 53 68 61 70 65 73 28 [0-10] 29 } //1
		$a_03_1 = {2c 20 4e 75 6c 6c 2c 20 [0-10] 2c } //1
		$a_03_2 = {2e 43 72 65 61 74 65 ?? 20 5f } //1
		$a_01_3 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 = GetObject("winmgmts:Win32_Process")
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}