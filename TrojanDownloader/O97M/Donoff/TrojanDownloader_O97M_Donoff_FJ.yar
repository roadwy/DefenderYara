
rule TrojanDownloader_O97M_Donoff_FJ{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FJ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 63 6f 73 28 90 05 05 04 30 2d 39 2e 29 20 90 03 01 01 2b 2d 20 41 63 6f 73 28 90 05 05 04 30 2d 39 2e 29 90 00 } //01 00 
		$a_03_1 = {4c 54 72 69 6d 28 22 90 02 20 22 29 20 2b 20 4c 54 72 69 6d 28 22 90 02 20 22 29 90 00 } //01 00 
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 } //00 00  Application.Run "
		$a_00_3 = {8f 83 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_FJ_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FJ,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2d 20 43 6f 73 28 90 04 05 06 61 2d 7a 41 2d 5a 29 20 2a 20 31 20 2d 20 43 68 72 28 90 04 05 03 30 2d 39 29 20 2f 20 90 04 05 03 30 2d 39 20 2d 20 43 68 72 42 28 90 00 } //01 00 
		$a_03_1 = {2b 20 43 53 6e 67 28 90 04 05 03 30 2d 39 29 20 2b 20 90 04 05 03 30 2d 39 20 2f 20 53 69 6e 28 90 04 05 03 30 2d 39 20 2d 20 43 42 79 74 65 28 90 04 05 03 30 2d 39 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}