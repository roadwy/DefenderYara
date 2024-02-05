
rule TrojanDownloader_O97M_Obfuse_FG{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FG,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //01 00 
		$a_01_1 = {4d 73 67 42 6f 78 20 22 48 65 6c 6c 6f 22 } //01 00 
		$a_01_2 = {50 72 69 76 61 74 65 20 53 75 62 20 57 6f 72 6b 73 68 65 65 74 5f 53 65 6c 65 63 74 69 6f 6e 43 68 61 6e 67 65 28 42 79 56 61 6c 20 54 61 72 67 65 74 20 41 73 20 52 61 6e 67 65 29 } //02 00 
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}