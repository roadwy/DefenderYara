
rule TrojanDownloader_O97M_Donoff_FC{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FC,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 53 74 72 43 6f 6e 76 28 44 65 63 6f 64 65 42 61 73 65 36 34 28 22 56 47 56 74 63 41 3d 3d 22 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 29 20 26 } //01 00 
		$a_00_1 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 22 54 22 20 26 20 22 65 22 20 26 20 22 6d 22 20 26 20 22 70 22 29 20 26 20 22 5c 31 73 2e 62 61 74 22 2c 20 76 62 48 69 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_FC_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FC,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {24 65 6e 76 3a 74 65 6d 70 20 2b 20 27 27 20 2b 20 24 90 02 10 2b 20 27 2e 65 78 65 27 90 00 } //01 00 
		$a_02_1 = {2e 44 6f 77 6e 6c 90 02 08 6f 61 64 46 69 6c 65 28 24 90 00 } //01 00 
		$a_00_2 = {53 74 61 22 20 2b 20 22 72 74 2d 50 72 6f 22 20 2b 20 22 63 65 73 73 } //01 00 
		$a_00_3 = {63 61 74 63 68 7b 77 72 69 74 65 2d 68 6f 73 74 } //01 00 
		$a_00_4 = {28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e } //00 00 
		$a_00_5 = {5d 04 00 } //00 30 
	condition:
		any of ($a_*)
 
}