
rule TrojanDownloader_O97M_Obfuse_JS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 61 73 64 61 78 61 73 64 61 73 78 61 73 64 61 73 64 73 64 64 6f 64 6b 61 73 6f 64 6b 61 6f 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_JS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 68 0b 00 00 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00 
		$a_00_1 = {55 52 10 00 00 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00 
		$a_00_2 = {43 3a 5c 55 73 65 72 73 5c 1f 00 00 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 48 65 6c 6c 6f 57 6f 72 6c 64 2e 65 78 65 } //01 00 
		$a_00_3 = {68 74 74 70 3a 2f 2f 39 33 2e 31 31 35 2e 31 39 2e 32 32 36 2f 65 76 6c 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_JS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 6f 62 6a 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 28 90 02 35 2c 20 4e 75 6c 6c 2c 20 6f 62 6a 43 6f 6e 66 69 67 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 29 90 00 } //01 00 
		$a_03_1 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 73 74 72 44 61 74 61 2c 20 90 02 10 2c 20 32 29 29 29 90 00 } //01 00 
		$a_01_2 = {2e 47 65 74 28 53 52 65 76 65 72 73 65 4d 6f 64 28 48 65 78 32 53 74 72 28 22 } //01 00 
		$a_01_3 = {26 20 53 74 72 52 65 76 65 72 73 65 28 4d 69 64 28 54 65 78 74 2c } //01 00 
		$a_01_4 = {3d 20 31 20 54 6f 20 4c 65 6e 28 73 74 72 44 61 74 61 29 20 53 74 65 70 20 32 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_JS_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 6d 64 20 2f 63 22 } //01 00 
		$a_01_1 = {22 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 22 } //01 00 
		$a_03_2 = {68 65 6f 2e 70 65 61 72 6c 6e 77 61 6c 74 65 72 73 2e 75 73 2f 90 02 05 2f 90 02 03 2e 65 78 65 90 0a 28 00 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_03_3 = {22 27 2c 27 25 74 65 6d 70 25 5c 90 02 05 2e 65 78 65 27 29 3b 73 74 61 72 74 20 25 74 65 6d 70 25 5c 90 1b 00 2e 65 78 65 22 90 00 } //01 00 
		$a_01_4 = {47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //01 00 
		$a_01_5 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 72 6f 6f 74 5c 63 69 6d 76 32 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //01 00 
		$a_01_6 = {6f 62 6a 2e 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 63 6d 64 2e 65 78 65 20 22 2c 20 22 2f 63 20 22 } //00 00 
	condition:
		any of ($a_*)
 
}