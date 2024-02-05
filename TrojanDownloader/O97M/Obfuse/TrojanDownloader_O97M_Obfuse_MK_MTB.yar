
rule TrojanDownloader_O97M_Obfuse_MK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 4e 62 75 65 6a 77 28 6d 65 75 68 77 29 } //01 00 
		$a_01_1 = {2e 54 65 78 74 2c 20 4a 4b 4d 4e 4e 65 32 2e 54 65 78 74 2c 20 38 37 34 2c 20 22 6e 75 6a 6e 65 67 35 33 22 } //01 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 6d 69 69 77 74 68 62 33 33 2c 20 6d 6e 77 75 69 75 62 68 32 32 2c 20 30 2c 20 30 } //01 00 
		$a_01_3 = {53 68 65 6c 6c 20 6d 65 75 68 77 } //00 00 
	condition:
		any of ($a_*)
 
}