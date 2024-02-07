
rule TrojanDownloader_O97M_Emotet_UP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.UP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 02 40 2e 20 5f 90 00 } //01 00 
		$a_03_1 = {43 72 65 61 74 65 28 90 02 20 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //01 00 
		$a_03_2 = {2e 47 72 6f 75 70 4e 61 6d 65 90 02 20 20 3d 20 53 70 6c 69 74 28 90 02 20 20 2b 20 90 02 08 28 54 72 69 6d 28 90 02 10 29 29 2c 90 00 } //01 00 
		$a_03_3 = {4a 6f 69 6e 28 90 02 20 2c 20 22 22 29 90 00 } //01 00 
		$a_01_4 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 46 61 6c 73 65 } //00 00  showwindow = False
	condition:
		any of ($a_*)
 
}