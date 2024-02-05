
rule TrojanDownloader_O97M_Donoff_EL{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EL,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 62 28 31 30 30 39 2c 20 31 30 39 34 2c 20 22 3b 2e 57 2d 7a 28 6a 64 70 2e 4f 69 73 28 46 44 3b 2e 51 74 49 29 20 65 74 2e 2e 74 63 42 74 49 20 45 3b 4d 65 68 63 58 73 72 65 71 2e 7a 74 4e 63 6a 28 71 54 55 4f 4b 24 65 49 70 77 74 55 29 56 6e 65 6c 6d 65 4f 6c 43 29 6a 65 3b 65 64 65 3a 74 3b } //00 00 
	condition:
		any of ($a_*)
 
}