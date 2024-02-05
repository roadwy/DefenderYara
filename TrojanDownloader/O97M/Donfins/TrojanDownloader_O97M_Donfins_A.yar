
rule TrojanDownloader_O97M_Donfins_A{
	meta:
		description = "TrojanDownloader:O97M/Donfins.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 90 05 0a 03 61 2d 7a 20 26 20 90 05 0a 03 61 2d 7a 20 26 20 90 05 0a 03 61 2d 7a 2c 20 46 61 6c 73 65 90 00 } //01 00 
		$a_01_1 = {50 72 69 6e 74 20 23 } //01 00 
		$a_01_2 = {43 6c 6f 73 65 20 23 } //01 00 
		$a_01_3 = {46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 } //01 00 
		$a_01_4 = {2e 46 72 65 65 53 70 61 63 65 20 3e 20 31 30 30 30 30 20 54 68 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}