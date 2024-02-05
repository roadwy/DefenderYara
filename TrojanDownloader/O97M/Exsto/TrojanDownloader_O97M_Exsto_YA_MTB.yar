
rule TrojanDownloader_O97M_Exsto_YA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Exsto.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 09 00 00 09 00 "
		
	strings :
		$a_01_0 = {54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //01 00 
		$a_01_2 = {2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 } //01 00 
		$a_01_3 = {2e 57 53 63 72 69 70 74 } //01 00 
		$a_01_4 = {53 68 65 6c 6c } //01 00 
		$a_01_5 = {77 69 6e 6d 67 6d 74 73 3a } //01 00 
		$a_01_6 = {45 6e 76 69 72 6f 6e 28 } //01 00 
		$a_01_7 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //01 00 
		$a_01_8 = {53 63 72 69 70 74 69 6e 67 2e } //00 00 
	condition:
		any of ($a_*)
 
}