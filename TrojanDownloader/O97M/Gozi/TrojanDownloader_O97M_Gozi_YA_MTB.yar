
rule TrojanDownloader_O97M_Gozi_YA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //01 00 
		$a_00_1 = {43 61 6c 6c 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //01 00 
		$a_00_2 = {68 74 74 70 3a 2f 2f 39 62 67 6e 71 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 } //01 00 
		$a_00_3 = {68 74 74 70 3a 2f 2f 64 37 75 61 70 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 68 74 74 70 3a 2f 2f 74 7a 65 31 2e 63 61 62 } //01 00 
		$a_00_4 = {68 74 74 70 3a 2f 2f 70 37 68 6e 65 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 74 7a 65 33 2e 63 61 62 22 2c 20 4a 4b } //01 00 
		$a_00_5 = {43 2e 74 6d 70 } //00 00 
	condition:
		any of ($a_*)
 
}