
rule TrojanDownloader_Linux_Bartallex_K{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.K,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 53 58 4d 4c 32 2e 58 22 } //01 00  = "SXML2.X"
		$a_01_1 = {3d 20 22 48 54 54 22 } //01 00  = "HTT"
		$a_03_2 = {3d 20 22 4d 22 20 2b 20 90 02 10 20 2b 20 22 4d 4c 22 20 2b 20 90 02 10 20 2b 20 22 50 22 90 00 } //01 00 
		$a_03_3 = {22 70 3a 2f 2f 70 22 20 2b 20 90 02 10 20 2b 20 22 65 62 69 22 20 2b 20 90 02 10 20 2b 20 22 6f 6d 2f 72 61 22 20 2b 20 90 02 10 20 2b 20 22 68 70 22 20 2b 20 90 02 10 20 2b 20 22 69 3d 22 90 00 } //01 00 
		$a_01_4 = {22 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 22 } //01 00  "ipting.FileSystem"
		$a_03_5 = {22 53 63 72 22 20 2b 20 90 02 10 20 2b 20 22 4f 62 6a 65 63 74 22 90 00 } //00 00 
		$a_00_6 = {5d 04 00 } //00 7b 
	condition:
		any of ($a_*)
 
}