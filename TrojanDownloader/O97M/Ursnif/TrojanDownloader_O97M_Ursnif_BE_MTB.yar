
rule TrojanDownloader_O97M_Ursnif_BE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.BE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 6c 73 78 2e 22 } //01 00 
		$a_03_1 = {4f 70 65 6e 20 53 74 72 52 65 76 65 72 73 65 28 90 02 10 29 20 26 20 22 5c 90 02 10 22 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 90 02 10 29 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //01 00 
		$a_01_2 = {44 65 62 75 67 2e 50 72 69 6e 74 20 45 72 72 6f 72 } //01 00 
		$a_01_3 = {3d 20 22 22 } //01 00 
		$a_01_4 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}