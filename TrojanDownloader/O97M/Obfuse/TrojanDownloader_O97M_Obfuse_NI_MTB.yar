
rule TrojanDownloader_O97M_Obfuse_NI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 14 2e 43 6f 6e 74 72 6f 6c 73 28 31 29 2e 56 61 6c 75 65 2c 20 54 72 75 65 29 90 00 } //01 00 
		$a_03_1 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 90 02 14 2e 43 6f 6e 74 72 6f 6c 73 28 30 29 2e 43 61 70 74 69 6f 6e 29 90 00 } //01 00 
		$a_01_2 = {2e 43 6f 6e 74 72 6f 6c 73 28 } //01 00 
		$a_01_3 = {2e 4f 70 65 6e } //01 00 
		$a_01_4 = {2e 43 6c 6f 73 65 } //01 00 
		$a_01_5 = {2e 56 61 6c 75 65 } //01 00 
		$a_01_6 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}