
rule TrojanDownloader_O97M_Obfuse_GJ{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GJ,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 50 4f 4c 4f 4c 53 28 29 } //01 00 
		$a_01_1 = {46 75 6e 63 74 69 6f 6e 20 48 45 48 45 48 45 48 45 28 29 } //01 00 
		$a_01_2 = {4d 6f 64 75 6c 65 31 2e 42 49 5a 41 52 44 } //01 00 
		$a_01_3 = {3d 20 53 68 65 6c 6c 28 6c 31 20 26 20 22 2f 63 22 20 26 20 61 31 31 2c 20 30 29 } //01 00 
		$a_01_4 = {3d 20 22 63 6d 64 22 20 26 20 22 2e 22 20 26 20 22 65 78 65 22 20 26 } //00 00 
	condition:
		any of ($a_*)
 
}