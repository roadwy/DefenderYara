
rule TrojanDownloader_O97M_Obfuse_LLB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LLB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 68 65 65 74 73 28 22 90 02 10 22 29 2e 43 65 6c 6c 73 28 90 02 03 2c 20 90 02 02 29 2e 56 61 6c 75 65 3a 90 00 } //1
		$a_03_1 = {53 68 65 6c 6c 20 90 02 c0 45 78 69 74 20 53 75 62 90 00 } //1
		$a_03_2 = {3d 20 43 4c 6e 67 28 90 02 20 20 26 20 4d 69 64 28 90 02 20 2c 20 90 02 20 2c 20 32 29 29 90 00 } //1
		$a_03_3 = {47 6f 54 6f 20 90 02 15 45 6e 64 20 53 75 62 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}