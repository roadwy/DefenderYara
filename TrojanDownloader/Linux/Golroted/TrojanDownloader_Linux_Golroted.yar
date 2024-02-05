
rule TrojanDownloader_Linux_Golroted{
	meta:
		description = "TrojanDownloader:Linux/Golroted,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 62 6c 6f 62 3f 64 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_03_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 22 90 02 20 2e 65 78 65 22 90 00 } //01 00 
		$a_01_2 = {67 65 2e 74 74 2f 61 70 69 2f } //01 00 
		$a_01_3 = {26 20 22 2e 74 74 2f 61 70 69 2f } //00 00 
		$a_00_4 = {cf 18 } //00 00 
	condition:
		any of ($a_*)
 
}