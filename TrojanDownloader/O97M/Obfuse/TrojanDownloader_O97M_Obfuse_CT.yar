
rule TrojanDownloader_O97M_Obfuse_CT{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CT,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 15 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 6c 6f 76 65 28 } //0a 00 
		$a_03_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 90 02 10 28 31 29 20 26 20 90 02 10 20 26 20 90 02 10 20 26 20 90 02 10 2c 20 30 29 90 00 } //01 00 
		$a_03_2 = {3d 20 4d 69 64 28 90 02 10 2c 20 90 02 10 2c 20 2d 90 10 04 00 20 2b 20 90 10 04 00 29 90 00 } //01 00 
		$a_03_3 = {3d 20 53 67 6e 28 90 02 07 29 90 00 } //01 00 
		$a_01_4 = {3d 20 53 67 6e 28 30 29 } //00 00 
	condition:
		any of ($a_*)
 
}