
rule TrojanDownloader_O97M_Emotet_VA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 02 40 2e 20 5f 90 00 } //01 00 
		$a_03_1 = {43 72 65 61 74 65 28 90 02 20 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //01 00 
		$a_03_2 = {53 65 74 20 90 02 20 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 73 29 90 02 20 2e 20 5f 90 0c 02 00 73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65 90 00 } //01 00 
		$a_03_3 = {3d 20 4a 6f 69 6e 28 90 02 20 2c 20 22 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}