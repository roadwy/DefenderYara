
rule TrojanDownloader_O97M_Obfuse_RI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {26 20 43 68 72 28 56 61 6c 28 22 26 22 20 26 20 22 48 22 90 02 04 26 20 4d 69 64 24 28 90 02 20 2c 90 00 } //01 00 
		$a_01_1 = {26 20 22 34 62 } //01 00 
		$a_01_2 = {26 20 22 35 } //01 00 
		$a_01_3 = {26 20 22 37 } //01 00 
		$a_01_4 = {3d 20 49 73 45 6d 70 74 79 28 22 22 29 } //01 00 
		$a_01_5 = {26 20 22 22 20 26 } //01 00 
		$a_01_6 = {3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //00 00 
	condition:
		any of ($a_*)
 
}