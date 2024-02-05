
rule TrojanDownloader_O97M_Emotet_QG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.QG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 69 6e 33 90 02 15 32 90 02 15 50 90 02 15 72 90 02 15 6f 90 02 15 63 90 02 15 65 90 02 15 73 90 02 15 73 90 02 15 22 29 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 25 20 2b 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 29 90 00 } //01 00 
		$a_03_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 15 28 90 02 15 20 2b 20 90 02 15 28 90 02 02 29 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}