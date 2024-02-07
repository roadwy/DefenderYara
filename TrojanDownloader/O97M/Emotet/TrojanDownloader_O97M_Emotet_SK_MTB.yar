
rule TrojanDownloader_O97M_Emotet_SK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 43 72 65 61 74 65 } //01 00  .Create
		$a_01_1 = {2b 20 28 22 53 54 41 52 54 55 22 29 } //01 00  + ("STARTU")
		$a_03_2 = {46 75 6e 63 74 69 6f 6e 90 02 18 28 29 90 0c 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 90 00 } //01 00 
		$a_03_3 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 90 0c 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 90 00 } //01 00 
		$a_03_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 90 05 0f 06 41 2d 5a 61 2d 7a 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}