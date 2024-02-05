
rule TrojanDownloader_O97M_FTCdedoc_G_MTB{
	meta:
		description = "TrojanDownloader:O97M/FTCdedoc.G!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 75 6e 20 90 02 05 2c 90 00 } //01 00 
		$a_03_1 = {2b 20 43 68 72 28 90 02 05 29 90 00 } //01 00 
		$a_01_2 = {3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //01 00 
		$a_01_3 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}