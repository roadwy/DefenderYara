
rule TrojanDownloader_O97M_Emotet_UN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.UN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 02 40 2e 20 5f 90 00 } //01 00 
		$a_03_1 = {43 72 65 61 74 65 28 90 02 20 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //01 00 
		$a_03_2 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65 90 02 08 52 65 44 69 6d 90 00 } //01 00 
		$a_03_3 = {4a 6f 69 6e 28 90 02 20 2c 20 22 22 29 90 00 } //01 00 
		$a_03_4 = {4c 6f 6f 70 90 02 06 52 65 44 69 6d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}