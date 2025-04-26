
rule TrojanDownloader_O97M_Obfuse_RVBU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {4f 70 65 6e 20 22 67 65 74 22 2c 20 [0-0f] 28 22 [0-64] 22 29 2c 20 46 61 6c 73 65 } //1
		$a_03_1 = {43 68 72 28 41 73 63 28 4d 69 64 28 [0-c8] 2c 20 [0-c8] 2c 20 31 29 29 20 2d 20 31 33 29 } //1
		$a_01_2 = {3d 20 43 68 72 28 35 30 29 20 2b 20 43 68 72 28 34 38 29 20 2b 20 43 68 72 28 34 38 29 } //1 = Chr(50) + Chr(48) + Chr(48)
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}