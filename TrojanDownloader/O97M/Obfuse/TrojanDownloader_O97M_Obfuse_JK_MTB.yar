
rule TrojanDownloader_O97M_Obfuse_JK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 6c 61 6f 74 6f 73 20 3d 20 22 70 22 } //01 00 
		$a_01_1 = {70 6f 6c 6f 6f 74 73 20 3d 20 22 68 22 } //01 00 
		$a_01_2 = {68 6f 74 67 75 61 73 65 20 3d 20 22 74 22 } //01 00 
		$a_01_3 = {6b 6f 61 73 6d 78 6a 77 20 3d 20 22 73 3a 2f 22 } //01 00 
		$a_01_4 = {6b 64 6a 6b 65 75 72 67 20 3d 20 22 2f 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 25 39 30 39 31 32 33 69 64 40 6a 2e 6d 70 5c 6b 61 73 73 61 61 73 64 73 6b 64 64 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_JK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 6d 64 20 2f 63 20 70 5e 22 20 26 20 22 6f 5e 22 20 26 20 22 77 5e 22 20 26 20 22 65 5e 22 20 26 20 22 72 5e 22 20 26 20 22 73 5e 22 20 26 20 22 68 5e 22 20 26 20 22 65 5e 22 20 26 20 22 6c 5e 22 20 26 20 22 6c 22 20 26 20 22 2e 22 20 26 20 22 65 22 20 26 20 22 78 22 20 26 20 22 65 22 20 26 20 22 20 22 } //01 00 
		$a_01_1 = {3d 20 22 20 2d 65 5e 22 20 26 20 22 6e 5e 63 20 22 } //01 00 
		$a_01_2 = {3d 20 22 20 2d 65 22 20 26 20 22 6e 63 20 22 } //01 00 
		$a_01_3 = {3d 20 22 20 2d 65 6e 63 20 22 } //00 00 
	condition:
		any of ($a_*)
 
}