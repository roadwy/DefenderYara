
rule TrojanDownloader_O97M_Obfuse_GK{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GK,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00 
		$a_03_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 14 20 2b 20 90 02 14 20 2b 20 90 02 10 29 2e 52 75 6e 24 20 90 02 30 20 2b 20 90 02 12 2c 20 76 62 48 69 64 65 90 00 } //01 00 
		$a_01_2 = {2b 20 22 70 74 2e 53 22 20 2b 20 22 68 65 6c 6c 22 } //01 00 
		$a_01_3 = {2b 20 22 57 73 63 72 69 22 } //01 00 
		$a_03_4 = {2a 20 43 53 74 72 28 90 02 07 20 2f 20 53 67 6e 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}