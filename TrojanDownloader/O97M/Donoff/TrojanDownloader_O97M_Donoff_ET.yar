
rule TrojanDownloader_O97M_Donoff_ET{
	meta:
		description = "TrojanDownloader:O97M/Donoff.ET,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 3a 22 20 2b 20 22 2f 2f 22 20 2b 20 68 61 6d 6d 65 72 20 2b 20 22 2f } //01 00 
		$a_01_1 = {2e 65 78 22 20 2b 20 22 65 7d 29 29 } //01 00 
		$a_01_2 = {67 61 6d 65 72 74 6f 6e 20 2b 20 22 65 22 } //00 00 
		$a_00_3 = {8f b6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_ET_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.ET,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 76 62 73 63 72 69 70 74 2e 72 65 67 65 78 70 22 29 } //01 00 
		$a_00_1 = {2e 47 6c 6f 62 61 6c 20 3d 20 } //01 00 
		$a_00_2 = {2e 50 61 74 74 65 72 6e 20 3d 20 } //01 00 
		$a_02_3 = {2e 52 65 70 6c 61 63 65 28 90 02 0f 2c 20 22 22 29 90 00 } //01 00 
		$a_00_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00 
		$a_00_5 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //9c ff 
		$a_00_6 = {68 74 74 70 3a 2f 2f 62 6b 61 69 6e 6c 69 6e 65 32 2f 66 69 6c 65 61 64 6d 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}