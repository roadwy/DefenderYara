
rule TrojanDownloader_O97M_Ursnif_AO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {26 20 22 5c 90 02 15 2e 78 73 6c 22 2c 20 31 29 90 00 } //01 00 
		$a_01_1 = {22 62 69 6e 2e 62 61 73 65 36 34 22 } //01 00 
		$a_01_2 = {23 49 66 20 56 42 41 37 20 54 68 65 6e } //01 00 
		$a_01_3 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 53 68 65 6c 6c 45 78 65 63 75 74 65 20 4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 } //01 00 
		$a_01_4 = {2e 54 65 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}