
rule TrojanDownloader_O97M_Emotet_QY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.QY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 28 90 02 35 2c 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 29 90 00 } //01 00 
		$a_03_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 20 28 90 02 20 2e 90 02 45 29 29 90 00 } //01 00 
		$a_01_2 = {2c 20 22 22 29 } //01 00 
		$a_03_3 = {52 65 70 6c 61 63 65 28 90 02 15 2c 20 90 02 15 2c 20 90 02 15 29 90 00 } //01 00 
		$a_03_4 = {3d 20 4d 73 67 42 6f 78 28 90 02 20 2e 90 02 20 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 90 02 20 2e 90 02 20 29 90 00 } //01 00 
		$a_03_5 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 90 02 05 44 69 6d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}