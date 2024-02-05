
rule TrojanDownloader_O97M_Emotet_SZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 68 69 6c 65 20 90 02 15 2e 43 72 65 61 74 65 28 90 02 08 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //01 00 
		$a_03_1 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 22 90 02 15 77 90 02 15 69 90 02 15 6e 90 02 15 6d 90 02 15 67 90 02 15 6d 90 02 15 74 90 02 15 73 90 02 15 3a 57 90 02 15 69 90 02 15 6e 90 02 15 33 90 02 15 32 90 02 15 22 2c 20 90 02 15 29 2c 20 22 22 29 90 00 } //01 00 
		$a_03_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 90 05 0f 06 41 2d 5a 61 2d 7a 2e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}