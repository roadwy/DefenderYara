
rule TrojanDownloader_O97M_Donoff_BF{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BF,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {3d 20 57 69 6e 45 78 65 63 28 22 63 6d 64 22 20 26 20 90 02 0a 20 26 20 22 2f 43 22 20 26 20 90 02 0a 20 26 20 90 02 0a 2c 20 90 02 0a 29 90 00 } //01 00 
		$a_02_1 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 03 20 2b 20 22 2e 65 78 65 22 2c 20 54 72 75 65 29 90 00 } //01 00 
		$a_00_2 = {53 75 62 20 44 6f 63 45 6e 74 72 79 28 29 } //01 00  Sub DocEntry()
		$a_00_3 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 43 45 52 54 49 46 49 43 41 54 45 2d 2d 2d 2d 2d } //00 00  -----BEGIN CERTIFICATE-----
	condition:
		any of ($a_*)
 
}