
rule TrojanDownloader_O97M_Donoff_EX{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 22 5e 78 65 5e 20 20 22 } //01 00 
		$a_00_1 = {2e 65 78 22 20 2b 20 22 65 } //01 00 
		$a_00_2 = {28 24 75 6d 2e 54 6f 53 74 72 69 6e 67 28 29 2c 20 24 70 70 29 3b } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_EX_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 22 5e 2e 65 5e 22 20 2b 20 22 78 5e 65 22 20 2b 20 22 5e 20 20 22 20 26 } //01 00 
		$a_00_1 = {24 6b 6f 73 3d 27 74 2e 77 65 27 3b 24 72 65 6d 3d 27 65 6e 74 29 2e 64 6f } //01 00 
		$a_00_2 = {2b 24 6e 69 6d 2b 27 68 74 74 70 73 3a 2f 2f } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_EX_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {22 70 6f 77 65 22 } //01 00 
		$a_00_1 = {22 74 2e 57 65 62 22 } //01 00 
		$a_03_2 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 24 90 01 10 90 02 10 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 90 00 } //01 00 
		$a_00_3 = {28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e } //00 00 
		$a_00_4 = {8f 77 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_EX_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 24 20 90 02 10 2c 20 30 90 00 } //01 00 
		$a_01_1 = {29 2e 72 27 2b 27 65 50 6c 61 27 2b 27 63 65 28 28 5b 43 68 61 52 5d } //01 00 
		$a_01_2 = {53 79 73 27 2b 27 74 27 2b 27 65 6d 2e 4e 65 74 } //01 00 
		$a_03_3 = {2f 2c 68 74 74 70 3a 2f 90 02 04 2b 90 02 04 2f 90 00 } //01 00 
		$a_03_4 = {27 2b 27 52 2e 65 78 65 90 02 04 27 2b 27 90 00 } //00 00 
		$a_00_5 = {8f 7c } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_EX_5{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 73 61 64 64 2c 20 6e } //01 00 
		$a_01_1 = {53 75 62 20 73 74 72 69 6e 67 73 5f 61 74 74 61 63 68 65 64 28 70 65 72 32 2c 20 42 79 52 65 66 20 61 72 67 31 29 } //01 00 
		$a_01_2 = {6e 20 3d 20 6d 20 2d } //01 00 
		$a_03_3 = {64 6f 63 5f 70 72 69 6e 74 5f 90 02 0b 46 6f 72 6d 31 2e 54 65 78 74 31 2c 20 65 78 74 31 2c 20 90 02 05 5f 6d 61 78 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_EX_6{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 53 74 72 43 6f 6e 76 28 44 65 63 6f 64 65 42 61 73 65 36 34 28 22 56 47 56 74 63 41 3d 3d 22 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 29 20 26 } //01 00 
		$a_00_1 = {53 74 72 43 6f 6e 76 28 44 65 63 6f 64 65 42 61 73 65 36 34 28 22 58 44 59 75 63 47 6c 6d 22 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 2c 20 76 62 48 69 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_EX_7{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 90 02 10 22 2c 20 90 02 10 2c 20 22 57 53 63 72 69 70 74 2e 22 90 00 } //01 00 
		$a_03_1 = {43 61 6c 6c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 10 20 2b 20 22 53 68 65 6c 6c 22 29 2e 52 75 6e 28 4d 6f 64 75 6c 65 31 2e 90 02 10 28 90 02 10 2c 20 22 22 29 2c 20 30 29 90 00 } //01 00 
		$a_03_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 90 02 10 2c 20 90 02 10 28 90 02 10 29 29 2c 20 22 22 29 90 00 } //01 00 
		$a_03_3 = {28 4d 69 64 28 90 02 10 2c 20 90 02 10 2c 20 31 29 29 20 2d 20 49 6e 74 28 4d 69 64 28 22 90 0f 20 00 90 00 } //00 00 
		$a_00_4 = {8f ea } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_EX_8{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {76 41 64 64 20 3d 20 22 7e 90 1d 07 00 22 90 00 } //01 00 
		$a_02_1 = {76 46 69 6c 65 4e 61 6d 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 90 1d 04 00 5c 22 90 00 } //01 00 
		$a_00_2 = {76 46 69 6c 65 4e 61 6d 65 20 3d 20 76 46 69 6c 65 4e 61 6d 65 20 2b 20 76 41 64 64 20 26 20 22 2e 65 22 20 2b 20 22 78 22 20 26 20 22 65 22 } //01 00 
		$a_02_3 = {7a 79 78 20 28 76 90 1d 04 00 4e 61 6d 65 29 90 00 } //01 00 
		$a_02_4 = {49 66 20 4e 6f 74 20 46 69 6c 65 45 78 69 73 74 73 28 76 46 69 6c 65 4e 61 6d 65 29 20 54 68 65 6e 20 53 61 76 65 90 02 06 20 76 46 69 6c 65 4e 61 6d 65 2c 20 90 02 0a 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 32 2e 43 61 70 74 69 6f 6e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_EX_9{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 22 70 6f 77 65 22 20 2b 20 22 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 24 } //01 00 
		$a_00_1 = {3d 20 6e 65 77 2d 6f 22 20 2b 20 22 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 3b 24 } //01 00 
		$a_00_2 = {3d 20 6e 65 77 2d 6f 22 20 2b 20 22 62 6a 65 63 74 20 72 61 6e 64 6f 6d 3b 24 73 74 72 20 3d 20 27 } //01 00 
		$a_02_3 = {3d 20 24 73 74 72 2e 53 70 6c 69 74 28 27 2c 27 29 3b 24 6e 61 6d 65 20 3d 20 24 90 12 0f 00 2e 6e 65 78 74 28 31 2c 20 36 35 35 33 36 29 3b 24 90 00 } //01 00 
		$a_00_4 = {3d 20 24 65 6e 76 3a 74 65 6d 70 20 2b 20 27 27 20 2b 20 24 6e 61 6d 65 20 2b 20 27 2e 65 78 65 27 3b 66 6f 72 65 61 63 68 28 24 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_EX_10{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 6e 6f 64 65 54 79 70 65 64 56 61 6c 75 65 29 90 0c 02 00 53 65 74 20 90 12 30 00 20 3d 20 4e 6f 74 68 69 6e 67 90 0c 02 00 53 65 74 20 90 12 30 00 20 3d 20 4e 6f 74 68 69 6e 67 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_03_1 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65 90 0c 02 00 6c 65 6e 67 68 74 20 3d 20 4c 65 6e 28 90 12 30 00 29 90 0c 02 00 49 66 20 6c 65 6e 67 68 74 20 3e 20 32 35 20 54 68 65 6e 90 00 } //01 00 
		$a_03_2 = {3d 20 32 20 54 68 65 6e 20 45 78 69 74 20 44 6f 90 0c 02 00 90 0e 10 00 90 12 20 00 20 28 90 12 20 00 29 90 0c 02 00 90 0e 10 00 4c 6f 6f 70 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 0c 02 00 53 75 62 20 41 75 74 6f 43 6c 6f 73 65 28 29 90 0c 02 00 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 90 12 20 00 22 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
		$a_00_3 = {96 30 } //00 00 
	condition:
		any of ($a_*)
 
}