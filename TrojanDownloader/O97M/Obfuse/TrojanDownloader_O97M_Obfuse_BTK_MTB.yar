
rule TrojanDownloader_O97M_Obfuse_BTK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BTK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //01 00 
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } //01 00 
		$a_01_2 = {3d 20 49 73 44 61 74 65 28 43 4c 6e 67 } //01 00 
		$a_01_3 = {66 41 75 70 44 50 30 39 5a 67 70 4e 2e 6b 6a 62 58 5f 32 5a 55 4e 5f 73 55 49 } //01 00 
		$a_01_4 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 58 47 4e 30 30 68 63 64 48 5a } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BTK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BTK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //01 00 
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } //01 00 
		$a_01_2 = {3d 20 49 73 44 61 74 65 28 43 4c 6e 67 } //01 00 
		$a_01_3 = {3d 20 5a 45 30 7a 5a 56 47 38 6e 7a 55 53 2e 41 49 75 45 5f 66 6f 79 5f 6f 61 4f 5f 4c 4e 72 30 } //01 00 
		$a_01_4 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 67 30 72 69 5f 49 6b 48 65 5f 36 79 61 5f 78 6d 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_BTK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BTK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //01 00 
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } //01 00 
		$a_01_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //01 00 
		$a_01_3 = {3d 20 44 74 6a 77 39 5f 63 39 75 52 5f 71 4c 6e 66 5f 76 71 69 2e 6e 42 58 59 4d 33 54 } //01 00 
		$a_01_4 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 45 69 62 49 32 30 30 34 36 43 35 } //00 00 
	condition:
		any of ($a_*)
 
}