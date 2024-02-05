
rule TrojanDownloader_O97M_Obfuse_BSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 54 38 2e 72 75 6e 28 68 6e 20 26 20 6d 20 26 20 22 33 32 20 22 20 2b 20 44 29 } //01 00 
		$a_01_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 44 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 55 62 2e 70 64 66 22 } //01 00 
		$a_01_2 = {4f 74 20 3d 20 4f 74 20 26 20 43 68 72 28 70 70 28 46 61 29 20 58 6f 72 20 31 29 } //01 00 
		$a_01_3 = {66 72 6d 2e 64 6f 77 6e 6c 6f 61 64 20 4b 72 2c 20 44 } //00 00 
	condition:
		any of ($a_*)
 
}