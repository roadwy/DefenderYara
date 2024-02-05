
rule TrojanDownloader_O97M_Emotet_VJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 90 02 20 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 90 02 20 2c 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //01 00 
		$a_03_1 = {3d 20 43 68 72 57 28 90 02 20 20 2b 20 77 64 4b 65 79 50 20 2b 20 90 02 20 29 90 00 } //01 00 
		$a_01_2 = {2b 20 53 74 72 52 65 76 65 72 73 65 28 64 73 65 29 29 } //01 00 
		$a_03_3 = {64 73 65 20 3d 20 90 02 20 2e 90 02 15 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 90 00 } //01 00 
		$a_03_4 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 90 02 15 20 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}