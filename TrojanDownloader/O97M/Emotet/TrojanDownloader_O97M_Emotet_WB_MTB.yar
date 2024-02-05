
rule TrojanDownloader_O97M_Emotet_WB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.WB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 90 02 20 2e 20 5f 90 00 } //01 00 
		$a_03_1 = {43 72 65 61 74 65 28 90 02 20 20 2b 20 90 02 20 20 2b 20 90 02 20 20 2b 20 90 02 15 2c 20 90 02 20 2c 20 90 02 20 29 90 00 } //01 00 
		$a_03_2 = {2b 20 43 68 72 57 28 90 02 20 2e 5a 6f 6f 6d 20 2b 20 90 02 05 20 2b 90 02 06 2b 20 90 02 20 2e 90 02 20 2e 54 61 67 20 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}