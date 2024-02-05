
rule TrojanDownloader_O97M_Ursnif_KAAQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.KAAQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 53 63 72 69 70 74 69 6e 67 2e 22 3a 20 78 44 77 77 20 3d 20 78 44 77 77 20 26 20 22 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 78 44 77 77 29 } //01 00 
		$a_01_2 = {62 74 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 30 20 2b 20 54 69 75 75 74 69 29 20 26 20 22 5c 22 20 26 20 47 47 20 26 20 22 2e 22 } //00 00 
	condition:
		any of ($a_*)
 
}