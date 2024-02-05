
rule TrojanDownloader_O97M_Emotet_QH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.QH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 32 5f 50 90 02 15 72 90 02 15 6f 90 02 15 63 90 02 15 65 90 02 15 73 90 02 15 73 90 02 15 22 29 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 25 20 2b 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}