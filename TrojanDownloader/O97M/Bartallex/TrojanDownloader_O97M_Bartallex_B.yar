
rule TrojanDownloader_O97M_Bartallex_B{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.B,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 20 6d 79 5f 66 69 6c 64 69 72 } //01 00 
		$a_00_1 = {54 65 6d 70 5c 22 20 2b 20 42 41 52 54 20 2b 20 43 68 72 28 33 34 29 } //01 00 
		$a_00_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}