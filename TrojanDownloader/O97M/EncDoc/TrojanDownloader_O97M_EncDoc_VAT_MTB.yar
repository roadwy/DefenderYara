
rule TrojanDownloader_O97M_EncDoc_VAT_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VAT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 73 65 65 6d 65 68 65 72 65 2e 67 61 2f 31 2e 65 78 65 } //01 00 
		$a_01_1 = {43 3a 5c 4a 72 72 65 52 73 50 5c 62 70 58 6f 61 65 45 5c 79 75 6a 45 74 6b 79 2e 65 78 65 } //01 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}