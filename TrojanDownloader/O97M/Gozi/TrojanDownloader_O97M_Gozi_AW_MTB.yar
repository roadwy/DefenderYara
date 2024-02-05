
rule TrojanDownloader_O97M_Gozi_AW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.AW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 22 43 3a 5c 75 73 65 72 73 5c 50 75 62 6c 69 63 5c 32 78 2e 6a 70 67 22 } //01 00 
		$a_00_1 = {3d 20 22 68 74 74 70 22 } //01 00 
		$a_03_2 = {28 22 3a 2f 2f 90 02 0f 2e 90 02 05 2f 70 61 6e 30 72 61 6d 69 63 30 2e 6a 70 67 22 29 90 00 } //01 00 
		$a_03_3 = {53 68 65 6c 6c 25 20 28 90 02 0f 20 2b 20 22 20 22 20 26 90 00 } //01 00 
		$a_00_4 = {2e 53 61 76 65 54 6f 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}