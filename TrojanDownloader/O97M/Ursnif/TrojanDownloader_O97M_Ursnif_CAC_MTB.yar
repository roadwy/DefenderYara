
rule TrojanDownloader_O97M_Ursnif_CAC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.CAC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 22 68 74 74 70 3a 2f 2f 39 79 67 77 32 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 6b 70 74 31 2e 63 61 62 22 2c 20 56 77 2c 20 30 2c 20 30 29 } //01 00 
		$a_01_1 = {22 55 2e 74 6d 70 22 } //01 00 
		$a_01_2 = {58 2e 72 75 6e 20 22 72 65 67 73 22 20 2b 20 22 76 72 33 32 20 22 20 26 20 56 77 } //01 00 
		$a_01_3 = {44 69 6d 20 58 20 41 73 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}