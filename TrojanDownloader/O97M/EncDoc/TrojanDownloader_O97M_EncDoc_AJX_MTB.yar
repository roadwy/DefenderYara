
rule TrojanDownloader_O97M_EncDoc_AJX_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AJX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 22 26 22 2f 22 26 22 2f 90 02 40 2e 90 02 25 2f 90 02 40 2f 72 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 90 00 } //01 00 
		$a_03_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 22 26 22 2f 90 02 60 2e 90 02 25 2f 90 02 40 2f 72 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 90 00 } //01 00 
		$a_03_2 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 22 26 22 2f 90 02 60 2e 90 02 25 2f 90 02 40 2f 72 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}