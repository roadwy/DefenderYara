
rule TrojanDownloader_O97M_Obfuse_RVBI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {22 22 22 65 78 65 2e 90 01 06 2f 90 01 04 2f 6d 6f 63 2e 6d 69 78 65 70 6c 75 74 2f 2f 3a 70 74 74 68 22 22 22 90 00 } //01 00 
		$a_03_1 = {22 22 22 65 78 65 2e 90 01 06 2f 90 01 04 2f 6d 6f 63 2e 65 6e 79 64 6c 65 6c 65 74 2f 2f 3a 73 70 74 74 68 22 22 22 90 00 } //03 00 
		$a_03_2 = {4d 69 64 28 90 02 0a 39 2c 20 90 02 0a 30 2c 20 31 29 90 00 } //03 00 
		$a_01_3 = {63 6d 64 31 28 58 78 58 2c 20 61 41 61 29 20 2b 20 55 52 4c 28 58 78 58 2c 20 61 41 61 29 20 2b 20 63 6d 64 32 28 58 78 58 2c 20 61 41 61 29 } //03 00 
		$a_01_4 = {41 75 74 6f 5f 4f 70 65 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_RVBI_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 38 67 30 66 2e 4f 70 65 6e 28 76 30 64 66 20 2b 20 22 5c 76 58 78 54 59 2e 62 61 74 22 29 } //01 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 22 20 2b 20 5a 58 44 64 7a 28 29 2e 4e 61 6d 65 73 70 61 63 65 28 55 53 45 52 5f 50 52 4f 46 49 4c 45 29 } //01 00 
		$a_01_2 = {4f 70 65 6e 20 46 6b 6e 6d 54 77 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //01 00 
		$a_01_3 = {47 65 74 4f 62 6a 65 63 74 28 43 65 6c 6c 73 28 31 30 36 2c 20 32 29 29 } //01 00 
		$a_01_4 = {57 6f 72 6b 62 6f 6f 6b 5f 41 63 74 69 76 61 74 65 28 29 0d 0a 43 65 6c 6c 73 28 32 2c 20 31 29 2e 56 61 6c 75 65 20 3d 20 31 } //00 00 
	condition:
		any of ($a_*)
 
}