
rule TrojanDownloader_O97M_MalSpam_C_MTB{
	meta:
		description = "TrojanDownloader:O97M/MalSpam.C!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 65 78 65 22 } //01 00 
		$a_01_1 = {22 2e 22 20 26 20 5f } //01 00 
		$a_03_2 = {24 45 4e 76 3a 74 65 4d 70 5c 90 02 10 2e 22 20 26 90 00 } //01 00 
		$a_01_3 = {22 22 20 26 20 22 20 22 20 26 } //01 00 
		$a_01_4 = {43 61 6c 6c 20 53 68 65 6c 6c 24 28 } //01 00 
		$a_01_5 = {3d 20 22 28 4e 45 77 2d 6f 62 6a 45 22 20 26 20 22 63 22 } //01 00 
		$a_01_6 = {3d 20 22 25 74 65 6d 70 25 22 20 26 } //01 00 
		$a_01_7 = {3d 20 22 5c 22 } //01 00 
		$a_01_8 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}