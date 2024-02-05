
rule TrojanDownloader_O97M_EncDoc_POKK_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.POKK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 22 63 75 72 6c 2e 65 78 65 20 2d 73 20 68 74 74 70 3a 2f 2f 37 38 2e 38 35 2e 31 37 2e 38 38 3a 38 34 34 33 2f 72 65 76 65 72 73 65 2e 70 73 31 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 61 73 6b 73 5c 72 65 76 61 2e 70 73 31 22 } //01 00 
		$a_01_2 = {41 75 74 6f 43 6c 6f 73 65 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}