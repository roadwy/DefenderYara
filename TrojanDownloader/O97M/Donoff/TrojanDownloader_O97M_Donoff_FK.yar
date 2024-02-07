
rule TrojanDownloader_O97M_Donoff_FK{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FK,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 44 62 6c 28 90 04 05 03 30 2d 39 29 29 20 2a 20 90 04 05 03 30 2d 39 20 2a 20 4f 63 74 28 90 04 05 03 30 2d 39 29 29 90 00 } //01 00 
		$a_03_1 = {43 42 79 74 65 28 90 04 05 03 30 2d 39 20 2a 20 54 61 6e 28 90 04 05 03 30 2d 39 29 20 2f 20 90 04 05 03 30 2d 39 20 2b 20 43 4c 6e 67 28 90 00 } //0a 00 
		$a_01_2 = {2b 20 53 68 65 6c 6c 28 } //00 00  + Shell(
	condition:
		any of ($a_*)
 
}