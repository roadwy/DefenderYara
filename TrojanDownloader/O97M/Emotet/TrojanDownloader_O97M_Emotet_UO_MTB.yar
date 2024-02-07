
rule TrojanDownloader_O97M_Emotet_UO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.UO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 6f 20 57 68 69 6c 65 20 90 02 40 2e 20 5f 90 00 } //01 00 
		$a_03_1 = {43 72 65 61 74 65 28 90 02 20 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //01 00 
		$a_03_2 = {2b 20 43 68 72 57 28 49 20 2b 20 77 64 4b 65 79 53 29 20 2b 20 22 90 02 30 77 90 02 30 69 90 02 30 6e 90 02 30 33 90 02 30 32 90 02 30 5f 90 02 30 22 20 2b 90 00 } //01 00 
		$a_01_3 = {3d 20 43 68 72 57 28 49 20 2b 20 77 64 4b 65 79 50 29 } //00 00  = ChrW(I + wdKeyP)
	condition:
		any of ($a_*)
 
}