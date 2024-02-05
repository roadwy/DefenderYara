
rule TrojanDownloader_O97M_Obfuse_RVBV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 61 70 70 64 61 74 61 26 63 68 72 28 61 73 63 28 63 29 2d 31 29 6e 65 78 74 74 6a 6e 69 75 62 69 6f 66 3d 61 70 70 64 61 74 61 65 6e 64 66 75 6e 63 74 69 6f 6e } //01 00 
		$a_01_1 = {69 6e 73 74 72 28 2c 6d 69 64 28 2c 67 2c 31 29 29 69 66 3e 30 74 68 65 6e 3d 6d 69 64 28 2c 2c 31 29 3d 2b 65 6c 73 65 3d 2b 6d 69 64 28 2c 67 2c 31 29 } //01 00 
		$a_01_2 = {3d 73 74 72 72 65 76 65 72 73 65 28 65 6e 63 29 66 6f 72 76 3d 31 74 6f 6c 65 6e 28 65 6e 63 29 63 3d 6d 69 64 28 65 6e 63 2c 5f 76 2c 5f 31 29 } //00 00 
	condition:
		any of ($a_*)
 
}