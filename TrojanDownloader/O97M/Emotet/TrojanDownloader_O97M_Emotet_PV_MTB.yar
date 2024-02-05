
rule TrojanDownloader_O97M_Emotet_PV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 22 6f 90 02 15 6e 90 02 15 33 90 02 15 32 90 02 20 50 90 02 15 72 90 02 15 6f 90 02 15 63 90 02 15 65 90 02 15 73 90 02 15 73 90 02 15 22 90 00 } //01 00 
		$a_03_1 = {2e 43 72 65 61 74 65 28 90 02 25 2c 20 90 02 25 2c 20 90 02 25 2c 20 90 02 25 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}