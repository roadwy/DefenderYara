
rule TrojanDownloader_O97M_Obfuse_CU{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CU,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 77 28 90 02 10 29 90 00 } //01 00 
		$a_02_1 = {44 69 6d 20 90 02 10 28 29 20 41 73 20 42 79 74 65 90 00 } //01 00 
		$a_01_2 = {3d 20 22 73 68 65 6c 6c 2e 65 78 65 20 22 } //01 00  = "shell.exe "
		$a_02_3 = {53 68 65 6c 6c 20 90 02 10 28 29 20 5f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}