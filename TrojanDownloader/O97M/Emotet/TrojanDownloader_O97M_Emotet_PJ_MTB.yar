
rule TrojanDownloader_O97M_Emotet_PJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 3a 57 69 90 02 20 6e 90 02 20 33 90 02 20 32 90 02 20 5f 90 02 20 50 90 02 20 72 90 02 20 6f 90 02 20 63 90 02 20 65 90 02 20 73 90 02 20 73 90 02 20 22 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 25 2c 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 29 90 00 } //01 00 
		$a_03_2 = {2e 43 61 70 74 69 6f 6e 20 2b 20 90 02 20 2e 90 02 25 2e 43 61 70 74 69 6f 6e 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}