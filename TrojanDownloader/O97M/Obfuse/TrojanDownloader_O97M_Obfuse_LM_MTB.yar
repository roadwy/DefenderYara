
rule TrojanDownloader_O97M_Obfuse_LM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {39 32 2e 36 33 2e 31 39 32 2e 32 31 36 2f 90 02 0a 2e 65 78 65 90 0a 23 00 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_00_1 = {43 6d 64 4c 69 6e 65 20 3d 20 22 22 22 22 20 26 20 46 69 6c 65 6e 61 6d 65 20 26 20 22 22 22 22 } //01 00  CmdLine = """" & Filename & """"
		$a_03_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 90 02 0c 2c 20 30 2c 20 30 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_LM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 14 28 22 77 61 5f 3a 77 61 5f 3a 77 69 77 61 5f 3a 6e 6d 67 77 61 5f 3a 6d 74 73 3a 77 61 5f 3a 57 77 61 5f 3a 77 61 5f 3a 77 61 5f 3a 69 77 61 5f 3a 6e 33 77 61 5f 3a 32 5f 50 77 61 5f 3a 72 6f 77 61 5f 3a 63 65 77 61 5f 3a 73 73 77 61 5f 3a 22 29 29 2e 43 72 65 61 74 65 28 90 02 14 2c 90 00 } //01 00 
		$a_03_1 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 90 02 14 29 20 2b 90 00 } //01 00 
		$a_01_2 = {2e 53 68 6f 77 57 69 6e 64 6f 77 21 20 3d } //00 00  .ShowWindow! =
	condition:
		any of ($a_*)
 
}