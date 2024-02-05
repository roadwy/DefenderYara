
rule TrojanDownloader_O97M_Bartallex_S{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.S,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } //01 00 
		$a_01_1 = {3d 20 31 20 54 6f 20 4c 65 6e 28 22 66 79 66 2f } //01 00 
		$a_01_2 = {3d 20 4d 69 64 28 22 66 79 66 2f } //01 00 
		$a_01_3 = {45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 54 45 4d 50 25 22 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 } //01 00 
		$a_01_4 = {26 20 43 68 72 28 41 73 63 28 } //00 00 
		$a_00_5 = {5d 04 00 } //00 a9 
	condition:
		any of ($a_*)
 
}