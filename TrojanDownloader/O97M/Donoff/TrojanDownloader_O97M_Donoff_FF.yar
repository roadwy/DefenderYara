
rule TrojanDownloader_O97M_Donoff_FF{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FF,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 22 61 70 22 20 26 20 22 70 64 61 74 61 22 29 20 26 20 22 5c 67 67 67 31 22 20 26 } //01 00 
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 28 30 26 2c 20 53 74 72 50 74 72 28 52 65 70 6c 61 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}