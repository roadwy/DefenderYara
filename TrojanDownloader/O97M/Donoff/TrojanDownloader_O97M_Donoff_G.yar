
rule TrojanDownloader_O97M_Donoff_G{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 45 6e 76 69 72 6f 6e 28 90 02 15 29 20 26 20 22 2f 74 73 78 33 22 20 2b 20 90 00 } //01 00 
		$a_01_1 = {3d 20 35 20 54 6f 20 4e 6c 0d 0a 44 6f 45 76 65 6e 74 73 0d 0a 4e 65 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_G_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {29 20 2d 20 31 20 54 6f 20 30 20 53 74 65 70 20 2d 32 } //02 00 
		$a_01_1 = {2e 54 79 70 65 20 3d 20 30 20 2b 20 31 } //02 00 
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 4d 6f 64 75 6c 65 33 2e } //01 00 
		$a_01_3 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //00 00 
		$a_00_4 = {8f 60 00 } //00 03 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_G_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 22 48 74 74 22 20 2b 20 22 70 22 20 2b 20 22 2e 22 } //01 00 
		$a_00_1 = {2c 20 22 6e 22 20 2b 20 22 6b 69 4f 22 20 2b 20 22 61 22 20 2b 20 22 57 73 22 20 2b 20 22 67 22 29 } //01 00 
		$a_00_2 = {3d 20 22 22 20 2b 20 22 22 20 2b 20 22 2e 65 22 20 2b 20 22 78 65 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_G_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2b 20 22 6c 22 20 2b 20 22 6c } //01 00 
		$a_00_1 = {64 69 73 6b 64 66 72 67 } //01 00 
		$a_00_2 = {47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 20 26 20 22 5c 22 20 2b 20 22 5c 22 } //01 00 
		$a_00_3 = {4f 62 61 6d 61 20 4e 75 6b } //01 00 
		$a_00_4 = {3d 20 22 22 20 2b 20 22 22 20 2b 20 22 2e 65 78 65 22 } //00 00 
		$a_00_5 = {8f 7f 00 } //00 03 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_G_5{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 90 02 20 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 25 74 65 6d 70 25 22 29 90 00 } //01 00 
		$a_01_1 = {20 26 20 22 5c 61 6d 6e 65 73 74 69 63 2e 65 78 65 22 } //01 00 
		$a_01_2 = {50 75 74 20 23 68 61 6e 61 70 65 72 2c 20 2c 20 43 42 79 74 65 28 22 26 22 20 2b 20 43 68 72 28 31 32 35 20 2d 20 35 33 29 20 26 20 66 72 61 75 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_G_6{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 22 20 2b 20 4c 43 61 73 65 28 65 72 72 6f 72 4d 73 67 29 20 2b 20 22 2e 58 4d 4c 48 22 20 2b 20 65 72 72 6f 72 4d 73 67 } //01 00 
		$a_01_1 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 50 72 6f 63 22 20 2b 20 61 72 67 75 6d 65 6e 74 73 20 2b 20 22 73 73 22 29 } //01 00 
		$a_01_2 = {2e 77 72 69 74 65 20 43 6f 64 4f 72 64 69 6e 65 43 6f 72 72 65 6e 74 65 31 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //01 00 
		$a_01_3 = {55 74 69 6c 73 49 6e 64 32 53 75 62 2e 73 61 76 65 74 6f 66 69 6c 65 20 64 69 6d 49 6e 64 65 78 41 72 67 73 2c 20 32 } //00 00 
		$a_00_4 = {8f } //ea 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_G_7{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 20 45 6e 76 69 72 6f 6e 28 53 74 72 52 65 76 65 72 73 65 28 63 63 6b 36 56 55 53 43 39 28 43 68 72 24 28 37 37 29 20 26 20 43 68 72 24 28 38 30 29 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 79 50 4a 4c 4c 63 41 75 31 20 26 20 43 68 72 24 28 39 32 29 20 26 20 43 68 72 24 28 31 32 30 29 20 26 20 43 68 72 24 28 31 32 30 29 20 26 20 43 68 72 24 28 34 36 29 } //01 00 
		$a_01_2 = {64 41 49 55 44 4e 41 55 49 44 42 61 73 69 64 61 38 79 64 61 62 73 75 20 30 2c 20 61 73 64 2c 20 79 50 4a 4c 4c 63 41 75 31 20 26 20 43 68 72 24 28 39 32 29 20 26 20 43 68 72 24 28 31 32 30 29 20 26 20 43 68 72 24 28 31 32 30 29 } //01 00 
		$a_01_3 = {61 73 64 20 3d 20 22 68 74 74 70 3a 2f 2f 22 20 26 20 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_G_8{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0c 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //01 00 
		$a_00_1 = {77 73 68 73 68 65 6c 6c 2e 72 75 6e } //01 00 
		$a_00_2 = {3d 20 77 73 68 73 68 65 6c 6c 2e 65 78 70 61 6e 64 65 6e 76 69 72 6f 6e 6d 65 6e 74 73 74 72 69 6e 67 73 28 } //01 00 
		$a_00_3 = {2e 73 61 76 65 74 6f 66 69 6c 65 } //01 00 
		$a_00_4 = {50 72 69 6e 74 20 } //01 00 
		$a_00_5 = {54 65 6d 70 } //01 00 
		$a_02_6 = {26 20 43 68 72 24 28 41 73 63 28 4d 69 64 24 28 90 02 0f 2c 20 49 2c 20 31 29 29 20 2b 20 41 73 63 28 4d 69 64 24 28 90 02 0f 2c 20 4a 2c 20 31 29 29 29 90 00 } //01 00 
		$a_02_7 = {73 68 65 6c 6c 90 04 01 02 20 28 90 00 } //01 00 
		$a_00_8 = {6b 69 6c 6c 20 } //01 00 
		$a_00_9 = {73 61 76 65 74 6f 66 69 6c 65 } //01 00 
		$a_00_10 = {73 65 74 20 77 73 68 73 68 65 6c 6c 20 3d 20 63 72 65 61 74 65 6f 62 6a 65 63 74 28 } //01 00 
		$a_00_11 = {74 68 65 6e 20 67 6f 74 6f 20 64 65 63 72 79 70 74 } //00 00 
		$a_00_12 = {e7 87 00 00 00 00 83 00 c0 ad } //a3 c7 
	condition:
		any of ($a_*)
 
}