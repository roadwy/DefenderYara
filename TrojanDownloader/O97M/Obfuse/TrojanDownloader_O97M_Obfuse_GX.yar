
rule TrojanDownloader_O97M_Obfuse_GX{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GX,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00 
		$a_03_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 90 02 14 28 31 29 20 2b 90 00 } //01 00 
		$a_01_2 = {2e 43 6f 6e 74 72 6f 6c 73 28 30 29 2e 56 61 6c 75 65 } //01 00 
		$a_03_3 = {2e 43 6f 6e 74 72 6f 6c 73 28 90 02 05 29 2e 56 61 6c 75 65 90 00 } //01 00 
		$a_03_4 = {2e 52 75 6e 21 20 28 90 02 20 29 20 2b 20 22 22 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}