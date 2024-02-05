
rule TrojanDownloader_O97M_Emotet_SO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 28 90 05 0f 06 41 2d 5a 61 2d 7a 28 90 00 } //01 00 
		$a_01_1 = {2b 20 28 22 53 54 41 52 54 55 22 29 } //01 00 
		$a_03_2 = {46 75 6e 63 74 69 6f 6e 20 90 02 14 28 90 02 20 29 90 02 06 44 69 6d 20 90 02 14 2c 90 00 } //01 00 
		$a_03_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 90 05 0f 06 41 2d 5a 61 2d 7a 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}