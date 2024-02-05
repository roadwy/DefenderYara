
rule TrojanDownloader_O97M_Emotet_VH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 02 40 2e 20 5f 90 00 } //01 00 
		$a_03_1 = {43 72 65 61 74 65 28 90 02 20 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //01 00 
		$a_03_2 = {4a 6f 69 6e 28 53 70 6c 69 74 28 90 02 45 2c 20 90 02 50 29 2c 20 22 22 29 90 00 } //01 00 
		$a_03_3 = {53 75 62 20 90 02 20 28 29 90 0c 02 00 44 65 62 75 67 2e 50 72 69 6e 74 20 22 64 68 68 68 68 68 65 65 22 20 2b 20 6e 73 77 77 77 20 2b 20 22 6f 70 65 6e 64 62 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}