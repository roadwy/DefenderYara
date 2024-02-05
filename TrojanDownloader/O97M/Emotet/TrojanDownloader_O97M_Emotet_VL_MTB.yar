
rule TrojanDownloader_O97M_Emotet_VL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 90 02 20 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 90 02 20 2c 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //01 00 
		$a_03_1 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 90 02 40 2c 20 90 02 30 29 90 00 } //01 00 
		$a_01_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 22 2d 65 20 22 } //01 00 
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 28 64 73 65 29 } //01 00 
		$a_03_4 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 90 02 12 20 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}