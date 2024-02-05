
rule TrojanDownloader_O97M_Donoff_FM{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FM,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 20 43 68 72 28 90 05 10 06 61 2d 7a 41 2d 5a 20 2b 20 38 30 20 2b 20 90 05 10 06 61 2d 7a 41 2d 5a 29 20 2b 20 22 6f 77 22 20 2b 20 22 65 72 73 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}