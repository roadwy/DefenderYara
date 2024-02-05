
rule TrojanDownloader_O97M_Emotet_RW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.RW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 90 02 04 54 72 69 6d 28 90 02 16 29 20 2b 90 00 } //01 00 
		$a_03_1 = {46 75 6e 63 74 69 6f 6e 90 02 14 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 90 00 } //01 00 
		$a_03_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 90 02 16 29 29 90 00 } //01 00 
		$a_03_3 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 90 02 02 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}