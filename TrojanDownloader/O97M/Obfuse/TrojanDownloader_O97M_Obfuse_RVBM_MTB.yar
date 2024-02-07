
rule TrojanDownloader_O97M_Obfuse_RVBM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 68 72 28 41 73 63 28 4d 69 64 28 90 02 c8 2c 20 90 02 c8 2c 20 31 29 29 20 2d 20 31 33 29 90 00 } //01 00 
		$a_03_1 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 6b 6e 6a 62 6b 37 67 62 35 62 6a 66 67 28 22 90 02 64 22 29 2c 20 46 61 6c 73 65 90 00 } //01 00 
		$a_03_2 = {3d 20 53 70 65 63 69 61 6c 50 61 74 68 20 2b 20 6b 6e 6a 62 6b 37 67 62 35 62 6a 66 67 28 22 90 02 24 22 29 90 00 } //01 00 
		$a_01_3 = {3d 20 43 68 72 28 35 30 29 20 2b 20 43 68 72 28 34 38 29 20 2b 20 43 68 72 28 34 38 29 } //00 00  = Chr(50) + Chr(48) + Chr(48)
	condition:
		any of ($a_*)
 
}