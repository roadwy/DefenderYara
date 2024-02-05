
rule TrojanDownloader_O97M_Donoff_EP{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EP,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 30 29 20 3d 20 22 77 73 63 72 69 22 } //01 00 
		$a_01_1 = {28 31 29 20 3d 20 22 70 74 2e 73 22 } //01 00 
		$a_01_2 = {28 32 29 20 3d 20 22 68 65 6c 6c 22 } //01 00 
		$a_03_3 = {3d 20 4a 6f 69 6e 28 90 01 0a 90 02 0a 2c 20 22 22 29 0d 0a 27 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}