
rule TrojanDownloader_O97M_EncDoc_TST_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.TST!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6e 69 63 73 2e 63 6f 2e 69 64 2f 79 66 74 78 64 72 75 2f } //01 00 
		$a_01_1 = {31 32 35 34 37 35 30 2e 70 6e 67 } //01 00 
		$a_01_2 = {43 3a 5c 54 65 73 74 5c 74 65 73 74 32 5c 46 69 6b 73 61 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}