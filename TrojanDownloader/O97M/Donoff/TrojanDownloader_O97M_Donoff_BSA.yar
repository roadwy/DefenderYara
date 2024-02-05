
rule TrojanDownloader_O97M_Donoff_BSA{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BSA,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 73 43 4c 2c 20 76 62 48 69 64 65 29 } //01 00 
		$a_03_1 = {68 74 74 70 3a 2f 2f 66 69 6c 65 72 90 02 01 2e 31 61 70 70 73 2e 63 6f 6d 2f 31 2e 74 78 74 90 00 } //01 00 
		$a_01_2 = {25 54 45 4d 50 25 20 26 26 20 63 74 20 2d 64 65 63 6f 64 65 20 2d 66 20 31 2e 74 78 74 20 31 2e 62 61 74 } //01 00 
		$a_01_3 = {26 26 20 64 65 6c 20 2f 66 20 2f 71 20 31 2e 74 78 74 20 26 26 20 31 2e 62 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}