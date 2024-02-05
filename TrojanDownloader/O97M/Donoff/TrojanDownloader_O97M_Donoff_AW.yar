
rule TrojanDownloader_O97M_Donoff_AW{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AW,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {28 43 68 72 24 28 90 01 03 29 20 2b 20 43 68 72 24 28 90 01 03 29 20 2b 20 43 68 72 24 28 90 01 03 29 20 2b 20 43 68 72 24 28 90 01 03 29 20 2b 20 43 68 72 24 28 90 01 03 29 90 00 } //01 00 
		$a_03_1 = {3d 20 53 74 72 43 6f 6e 76 28 90 02 10 28 29 2c 20 28 90 10 03 00 20 2b 20 90 10 03 00 20 2b 20 90 10 03 00 20 2d 20 90 10 03 00 20 2b 20 90 10 03 00 20 2b 20 90 10 03 00 20 2b 20 90 10 03 00 20 2d 20 90 10 03 00 29 20 2b 20 28 90 10 03 00 20 2b 20 90 10 03 00 20 2b 90 00 } //01 00 
		$a_03_2 = {3d 20 31 20 54 68 65 6e 20 44 65 62 75 67 2e 41 73 73 65 72 74 20 4e 6f 74 20 90 12 10 00 28 90 10 03 00 29 90 00 } //01 00 
		$a_03_3 = {46 6f 72 20 90 02 10 20 3d 20 30 20 54 6f 20 28 90 10 03 00 20 2b 20 90 10 03 00 20 2b 20 90 10 03 00 20 2d 20 90 10 03 00 20 2b 20 90 10 03 00 20 2b 20 90 10 03 00 20 2b 20 90 10 03 00 20 2d 20 90 10 03 00 20 2d 20 90 10 03 00 29 90 00 } //01 00 
		$a_03_4 = {3d 20 28 49 6e 74 28 90 02 14 20 2f 20 28 90 10 03 00 20 5e 20 28 90 10 03 00 20 2a 20 28 90 10 03 00 20 2d 20 90 02 14 29 29 29 29 29 20 41 6e 64 20 28 28 90 10 03 00 20 5e 20 90 10 03 00 29 20 2d 20 90 10 03 00 29 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 7d 
	condition:
		any of ($a_*)
 
}