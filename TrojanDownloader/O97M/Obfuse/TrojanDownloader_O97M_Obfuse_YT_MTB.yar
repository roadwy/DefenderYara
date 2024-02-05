
rule TrojanDownloader_O97M_Obfuse_YT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.YT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 31 2e 63 6f 6d } //01 00 
		$a_01_1 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 31 2e 78 73 6c } //01 00 
		$a_01_2 = {66 72 6d 2e 74 65 78 74 62 6f 78 31 2e 74 65 78 74 } //01 00 
		$a_01_3 = {43 68 72 28 33 34 29 } //01 00 
		$a_01_4 = {43 61 6c 6c 20 56 42 41 2e 46 69 6c 65 43 6f 70 79 28 61 76 6d 79 49 77 2c 20 61 36 32 4e 42 29 } //01 00 
		$a_01_5 = {28 22 63 6f 6d 6d 65 6e 74 73 22 29 20 26 20 61 65 30 53 44 4f } //00 00 
	condition:
		any of ($a_*)
 
}