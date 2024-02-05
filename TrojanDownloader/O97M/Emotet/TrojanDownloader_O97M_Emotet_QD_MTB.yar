
rule TrojanDownloader_O97M_Emotet_QD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.QD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 43 61 70 74 69 6f 6e 20 2b 20 90 02 15 2e 90 02 15 2e 43 61 70 74 69 6f 6e 29 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 25 20 2b 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 29 90 00 } //01 00 
		$a_03_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 15 28 90 02 15 20 2b 20 90 02 15 28 90 02 02 29 29 29 90 00 } //01 00 
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 90 02 20 2c 20 90 02 20 2c 20 22 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}