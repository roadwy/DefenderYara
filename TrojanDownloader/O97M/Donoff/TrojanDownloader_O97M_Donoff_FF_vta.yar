
rule TrojanDownloader_O97M_Donoff_FF_vta{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FF!vta,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 22 61 70 70 22 20 26 20 22 22 20 26 20 22 64 61 74 61 22 29 20 26 20 22 5c } //01 00 
		$a_01_1 = {2e 65 22 20 26 20 22 78 22 20 26 20 22 65 } //01 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 28 30 26 2c 20 53 74 72 50 74 72 28 52 65 70 6c 61 63 65 28 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}