
rule TrojanDownloader_O97M_Donoff_HZA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.HZA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 69 75 71 32 34 2e 76 62 73 } //01 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 71 6e 6e 34 35 35 2e 74 78 74 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00 
		$a_01_3 = {45 78 63 65 6c 5c 53 65 63 75 72 69 74 79 5c 56 42 41 57 61 72 6e 69 6e 67 73 } //00 00 
	condition:
		any of ($a_*)
 
}