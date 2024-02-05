
rule TrojanDownloader_O97M_Donoff_FA_vta{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FA!vta,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 65 22 20 26 20 22 78 65 22 29 } //01 00 
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 20 30 26 2c 20 52 65 70 6c 61 63 65 28 } //02 00 
		$a_03_2 = {22 2c 20 22 22 29 2c 20 90 01 08 90 02 20 2c 20 30 26 2c 20 30 26 90 00 } //00 00 
		$a_00_3 = {8f 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_FA_vta_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FA!vta,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 26 20 22 5c 22 20 26 20 22 6d 79 66 69 6c 65 65 70 65 70 65 2e 65 78 65 } //01 00 
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 20 30 26 2c 20 53 74 72 50 74 72 28 52 65 70 6c 61 63 65 28 } //01 00 
		$a_01_2 = {22 2c 20 22 22 29 29 2c 20 53 74 72 50 74 72 28 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}