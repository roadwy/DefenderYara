
rule TrojanDownloader_O97M_Obfuse_DL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 30 2e 33 2e 31 31 2e 32 33 2e 32 30 2e 39 2e 33 30 2e 39 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 61 6c 38 69 62 20 26 20 22 20 22 20 26 20 61 6e 6b 39 41 } //01 00 
		$a_01_2 = {53 68 65 6c 6c 20 61 32 45 53 36 47 20 26 20 22 20 22 20 26 20 61 67 72 58 33 42 } //01 00 
		$a_01_3 = {54 72 69 6d 28 61 41 50 5a 42 6f 20 58 6f 72 20 61 55 49 7a 34 6b 29 } //01 00 
		$a_01_4 = {54 72 69 6d 28 61 66 44 32 37 45 20 58 6f 72 20 61 65 78 33 76 46 29 } //00 00 
	condition:
		any of ($a_*)
 
}