
rule TrojanDownloader_O97M_Obfuse_PDR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 28 22 63 75 72 6c 20 68 74 74 70 3a 2f 2f 77 77 77 2e 62 6f 6f 6b 69 71 2e 62 73 6e 6c 2e 63 6f 2e 69 6e 2f 64 61 74 61 5f 65 6e 74 72 79 2f 63 69 72 63 75 6c 61 72 73 2f 6d 90 02 05 61 90 02 05 63 2e 65 78 65 90 00 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 28 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 61 2e 65 78 65 22 29 } //00 00  Shell ("C:\Users\Public\a.exe")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_PDR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 90 02 03 77 73 68 73 68 65 6c 6c 90 00 } //01 00 
		$a_03_1 = {73 70 65 63 69 61 6c 70 61 74 68 3d 90 02 03 77 73 68 73 68 65 6c 6c 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 90 02 0a 22 29 64 69 6d 64 69 6d 90 00 } //01 00 
		$a_03_2 = {3d 73 70 65 63 69 61 6c 70 61 74 68 2b 28 22 90 02 0a 2e 22 29 2e 6f 70 65 6e 22 67 65 74 22 2c 28 22 68 3a 2f 2f 77 77 77 2e 64 2e 6d 2f 6d 62 2f 76 68 76 6a 68 67 62 76 76 6d 68 2e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}