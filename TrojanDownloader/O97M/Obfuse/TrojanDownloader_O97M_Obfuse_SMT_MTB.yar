
rule TrojanDownloader_O97M_Obfuse_SMT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SMT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 22 22 90 02 25 5c 70 6d 2e 6a 5c 5c 3a 73 70 74 74 68 22 22 22 22 20 20 20 20 20 20 61 74 68 73 6d 22 22 22 29 90 00 } //01 00 
		$a_03_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 90 02 0a 2c 20 31 29 90 00 } //01 00 
		$a_01_2 = {53 75 62 20 43 61 6c 63 75 6c 61 74 6f 72 5f 43 6c 69 63 6b 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}