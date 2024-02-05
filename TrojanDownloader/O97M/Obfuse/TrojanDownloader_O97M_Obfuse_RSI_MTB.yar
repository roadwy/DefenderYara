
rule TrojanDownloader_O97M_Obfuse_RSI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RSI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00 
		$a_01_1 = {43 61 6c 6c 20 63 35 61 33 32 34 34 65 2e 65 78 65 63 28 64 65 38 36 66 36 38 61 29 } //01 00 
		$a_01_2 = {61 30 65 31 61 35 36 31 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 66 38 61 33 30 31 61 65 28 31 29 2c 20 46 61 6c 73 65 } //01 00 
		$a_01_3 = {53 70 6c 69 74 28 66 30 62 61 38 34 31 64 2c 20 22 7c 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}