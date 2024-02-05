
rule TrojanDownloader_O97M_Obfuse_JI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 29 } //01 00 
		$a_03_1 = {43 61 6c 6c 20 90 02 09 28 90 02 09 2e 90 02 09 2c 20 22 76 65 72 69 6e 73 74 65 72 65 2e 78 6c 73 22 2c 20 30 29 90 00 } //01 00 
		$a_03_2 = {53 70 6c 69 74 28 90 02 09 2c 20 76 62 4e 65 77 4c 69 6e 65 29 90 00 } //01 00 
		$a_01_3 = {2e 44 6f 63 75 6d 65 6e 74 2e 62 6f 64 79 2e 69 6e 6e 65 72 54 65 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}