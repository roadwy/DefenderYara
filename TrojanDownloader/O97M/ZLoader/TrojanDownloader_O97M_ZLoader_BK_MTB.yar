
rule TrojanDownloader_O97M_ZLoader_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/ZLoader.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 63 6f 63 69 6e 61 73 68 6f 67 61 72 6d 6f 62 69 6c 69 61 72 69 6f 2e 63 6f 6d 2f 70 68 6f 74 6f 2e 70 6e 67 } //01 00 
		$a_01_1 = {63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 70 68 6f 74 6f 2e 70 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}