
rule TrojanDownloader_O97M_Ursnif_KAAV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.KAAV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 44 53 77 2e 74 68 33 32 50 72 6f 63 65 73 73 49 44 } //01 00 
		$a_01_1 = {3d 20 53 70 6c 69 74 28 52 61 6e 67 65 28 22 49 37 39 3a 49 37 39 22 29 2c 20 22 2c 22 29 } //01 00 
		$a_01_2 = {57 6f 72 6b 62 6f 6f 6b 73 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 44 69 73 70 6c 61 79 41 6c 65 72 74 73 20 3d 20 42 6e 3a 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 51 75 69 74 } //01 00 
		$a_01_3 = {70 69 6e 6e 53 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 74 79 20 26 20 22 2e 22 } //00 00 
	condition:
		any of ($a_*)
 
}