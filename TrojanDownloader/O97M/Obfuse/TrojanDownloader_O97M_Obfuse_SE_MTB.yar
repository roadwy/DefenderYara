
rule TrojanDownloader_O97M_Obfuse_SE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 46 69 65 6c 64 73 2e 49 74 65 6d 28 90 02 03 29 2e 4f 4c 45 46 6f 72 6d 61 74 2e 4f 62 6a 65 63 74 2e 47 72 6f 75 70 4e 61 6d 65 90 00 } //01 00 
		$a_03_1 = {2e 50 61 72 61 67 72 61 70 68 73 28 90 02 45 29 2e 52 61 6e 67 65 2e 54 65 78 74 90 00 } //01 00 
		$a_03_2 = {2e 49 74 65 6d 28 29 2e 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 90 02 20 2c 90 00 } //01 00 
		$a_01_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 22 2c 20 4e 75 6c 6c 2c 20 30 20 2a 20 31 } //01 00  C:\Windows\System32", Null, 0 * 1
		$a_01_4 = {3d 20 22 22 } //00 00  = ""
	condition:
		any of ($a_*)
 
}