
rule TrojanDownloader_O97M_Obfuse_QWE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.QWE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 73 74 61 74 62 6c 6f 67 67 65 72 2e 63 6f 6d 2f 68 65 61 64 65 72 2e 6a 70 67 } //01 00 
		$a_01_1 = {43 3a 5c 75 73 65 72 73 5c 50 75 62 6c 69 63 5c 22 20 2b 20 22 77 74 2e 6a 70 67 22 } //01 00 
		$a_01_2 = {53 68 65 6c 6c 25 20 28 43 6f 75 6e 74 65 72 56 62 20 2b 20 22 20 22 } //01 00 
		$a_01_3 = {50 72 6f 63 65 64 75 72 65 42 75 66 42 75 66 66 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}