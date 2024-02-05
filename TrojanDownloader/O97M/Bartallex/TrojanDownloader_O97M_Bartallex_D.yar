
rule TrojanDownloader_O97M_Bartallex_D{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.D,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 41 52 54 20 2b 20 43 68 72 28 33 33 20 2b 20 31 29 } //01 00 
		$a_00_1 = {4b 69 6c 6c 20 4d 59 5f 46 49 4c 45 4e 44 49 52 } //01 00 
		$a_00_2 = {43 68 72 28 41 73 63 28 22 65 22 29 29 20 2b 20 43 68 72 28 41 73 63 28 22 78 22 29 29 20 2b 20 43 68 72 28 41 73 63 28 22 65 22 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}