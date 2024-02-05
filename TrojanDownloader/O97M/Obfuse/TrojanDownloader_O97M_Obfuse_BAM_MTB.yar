
rule TrojanDownloader_O97M_Obfuse_BAM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BAM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 53 75 62 20 61 73 64 61 73 28 29 } //01 00 
		$a_01_1 = {3d 20 31 20 54 6f 20 4c 65 6e 28 6d 4b 4d 4d 49 4d 43 4f 69 61 74 41 61 6a 6a 70 52 75 66 5a 4f 49 6a 48 5a 71 46 62 46 6d 58 4d 6a 4d 4d 4b 6e 48 56 72 72 75 7a 41 4a 29 20 53 74 65 70 20 32 } //01 00 
		$a_01_2 = {3d 20 73 53 74 72 20 2b 20 43 68 72 28 43 4c 6e 67 28 22 26 48 22 20 26 20 4d 69 64 28 6d 4b 4d 4d 49 4d 43 4f 69 61 74 41 61 6a 6a 70 52 75 66 5a 4f 49 6a 48 5a 71 46 62 46 6d 58 4d 6a 4d 4d 4b 6e 48 56 72 72 75 7a 41 4a 2c 20 69 2c 20 32 29 29 20 2d 20 32 39 29 } //01 00 
		$a_01_3 = {53 68 65 6c 6c 20 73 53 74 72 } //00 00 
	condition:
		any of ($a_*)
 
}