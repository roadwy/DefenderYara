
rule TrojanDownloader_O97M_Bartallex_E{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.E,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 41 52 54 20 2b 20 43 68 72 28 33 33 20 2b 20 31 29 } //01 00 
		$a_00_1 = {4b 69 6c 6c 20 4d 59 5f 46 49 4c 45 4e 44 49 52 } //01 00 
		$a_00_2 = {43 68 72 28 33 34 29 20 2b 20 22 34 2e 65 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 2b 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 78 65 22 20 2b 20 43 68 72 28 33 34 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Bartallex_E_2{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.E,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 4d 6f 64 75 6c 65 31 2e 47 6f 61 62 63 28 4d 4f 54 4f 52 4f 4c 41 29 20 2b 20 4b 49 50 41 52 49 53 } //01 00 
		$a_00_1 = {3d 20 4d 6f 64 75 6c 65 31 2e 4b 61 6c 79 6d 61 28 42 45 52 49 4c 4b 41 29 20 2b 20 41 4e 44 4f 4b 41 4e 41 } //02 00 
		$a_00_2 = {41 54 54 48 20 3d 20 68 68 72 28 4e 64 6a 73 29 20 2b 20 43 68 72 28 4e 64 6a 73 20 2b 20 31 32 29 20 2b 20 43 68 72 28 4e 64 6a 73 20 2b 20 31 32 29 20 2b 20 43 68 72 28 } //02 00 
		$a_00_3 = {42 42 54 48 20 3d 20 50 48 32 20 2b 20 4d 41 44 52 49 44 20 2b 20 22 2e 62 61 74 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Bartallex_E_3{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.E,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 65 64 69 73 74 72 69 62 75 74 65 20 3d 20 52 65 64 69 73 74 72 69 62 75 74 65 20 26 20 43 68 72 28 5a 28 6e 29 20 2d 20 39 20 2a 20 6f 6c 64 4c 65 6e } //01 00 
		$a_00_1 = {20 6b 6d 61 44 65 63 6f 64 65 55 52 4c 20 3d 20 52 65 70 6c 61 63 65 28 6b 6d 61 44 65 63 6f 64 65 55 52 4c 2c 20 45 53 43 53 74 72 69 6e 67 2c 20 43 68 72 28 45 53 43 56 61 6c 75 65 29 29 } //01 00 
		$a_00_2 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //01 00 
		$a_00_3 = {57 6f 72 6b 4c 6f 6e 67 75 65 20 3d 20 41 72 72 61 79 28 35 } //01 00 
		$a_00_4 = {44 65 63 6f 64 65 47 4d 54 44 61 74 65 20 3d 20 44 65 63 6f 64 65 47 4d 54 44 61 74 65 20 2b 20 43 44 61 74 65 28 57 6f 72 6b 53 74 72 69 6e 67 29 20 2b 20 34 20 2f 20 32 34 } //00 00 
	condition:
		any of ($a_*)
 
}