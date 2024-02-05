
rule TrojanDownloader_O97M_Obfuse_AW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00 
		$a_00_1 = {67 68 68 66 67 66 67 64 73 66 61 73 2e 52 65 67 57 72 69 74 65 20 68 67 66 68 66 66 73 61 64 73 61 28 61 29 } //01 00 
		$a_00_2 = {67 68 68 66 67 66 67 64 73 66 61 73 2e 52 75 6e 20 28 68 67 66 68 66 66 73 61 64 73 61 28 63 29 } //01 00 
		$a_00_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 61 69 74 20 28 4e 6f 77 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 30 3a 30 30 3a 30 37 22 29 } //01 00 
		$a_00_4 = {67 68 68 66 67 66 67 64 73 66 61 73 2e 52 65 67 44 65 6c 65 74 65 20 68 67 66 68 66 66 73 61 64 73 61 28 64 29 } //01 00 
		$a_00_5 = {3d 20 73 53 74 72 20 2b 20 43 68 72 28 43 4c 6e 67 28 22 26 48 22 20 26 20 4d 69 64 28 73 74 72 2c 20 69 2c 20 32 29 29 20 2d 20 31 32 29 } //01 00 
		$a_00_6 = {36 46 37 39 37 30 32 43 33 42 36 46 32 43 37 43 36 41 37 42 38 33 37 31 37 45 37 46 37 34 36 41 37 31 37 38 36 41 37 38 32 43 33 39 38 33 32 43 33 44 32 43 34 44 37 30 37 30 33 39 35 39 37 43 35 43 37 45 37 31 } //00 00 
	condition:
		any of ($a_*)
 
}