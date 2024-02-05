
rule TrojanDownloader_O97M_Donoff_DRE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DRE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 72 28 64 73 5f 66 20 2d 20 37 37 29 } //01 00 
		$a_01_1 = {64 5f 66 67 28 31 36 34 29 20 26 20 64 5f 66 67 28 31 36 30 29 20 26 20 64 5f 66 67 28 31 34 34 29 20 26 20 64 5f 66 67 28 31 39 31 29 20 26 20 64 5f 66 67 28 31 38 32 29 20 26 20 64 5f 66 67 28 31 38 39 29 20 26 20 64 5f 66 67 28 31 36 31 29 20 26 20 64 5f 66 67 28 31 32 33 29 20 26 20 64 5f 66 67 28 31 39 32 29 20 26 20 64 5f 66 67 28 31 34 39 29 20 26 20 64 5f 66 67 28 31 34 36 29 20 26 20 64 5f 66 67 28 31 38 35 29 20 26 20 64 5f 66 67 28 31 35 33 29 } //01 00 
		$a_01_2 = {67 66 67 68 62 20 62 76 63 76 6e 62 63 20 62 76 63 6e 63 6d } //00 00 
	condition:
		any of ($a_*)
 
}