
rule TrojanDownloader_O97M_Emotet_RA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {5c 73 6f 61 6d 90 01 01 2e 4f 43 58 90 00 } //01 00 
		$a_03_1 = {5c 73 6f 61 6d 90 01 01 2e 6f 63 78 90 00 } //05 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //05 00 
		$a_01_3 = {75 72 6c 6d 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Emotet_RA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 28 90 02 35 2c 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 29 90 00 } //01 00 
		$a_03_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 20 28 90 02 20 2e 90 02 45 29 29 90 00 } //01 00 
		$a_03_2 = {2e 52 65 70 6c 61 63 65 90 02 01 28 90 02 15 2c 20 90 02 15 2e 90 02 18 2c 20 22 22 29 90 00 } //01 00 
		$a_03_3 = {3d 20 4d 73 67 42 6f 78 28 90 02 20 2e 90 02 20 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 90 02 20 2e 90 02 20 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}