
rule TrojanDownloader_O97M_Emotet_VI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 02 40 2e 20 5f 90 00 } //01 00 
		$a_03_1 = {43 72 65 61 74 65 28 90 02 20 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //01 00 
		$a_03_2 = {2b 20 22 2d 65 20 22 90 02 20 20 3d 20 5f 90 0c 02 00 22 70 69 7a 64 65 63 22 90 00 } //01 00 
		$a_03_3 = {2b 20 22 2d 65 20 22 90 02 20 20 3d 20 5f 90 0c 02 00 22 4d 43 45 22 90 00 } //01 00 
		$a_03_4 = {2b 20 53 74 72 52 65 76 65 72 73 65 28 64 73 65 29 29 90 02 20 20 3d 20 5f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}