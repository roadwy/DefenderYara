
rule TrojanDownloader_O97M_Donoff_N{
	meta:
		description = "TrojanDownloader:O97M/Donoff.N,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {27 61 73 64 77 90 02 ff 0a 53 65 74 20 90 02 18 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 04 08 03 41 2d 5a 90 05 10 03 41 2d 5a 29 90 00 } //01 00 
		$a_01_1 = {3d 20 31 20 2d 20 28 41 74 6e 28 32 30 29 29 } //05 00 
		$a_01_2 = {2b 20 43 68 72 28 49 6e 74 28 31 32 31 20 2a 20 52 6e 64 29 20 2b 20 39 37 29 } //00 00 
	condition:
		any of ($a_*)
 
}