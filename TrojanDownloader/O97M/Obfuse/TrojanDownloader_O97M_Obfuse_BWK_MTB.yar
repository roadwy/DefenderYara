
rule TrojanDownloader_O97M_Obfuse_BWK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BWK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 64 6d 66 64 22 2c 20 22 22 29 } //01 00 
		$a_01_1 = {3d 20 22 2e 22 20 26 20 69 6e 73 74 61 6c 6c 4d 69 78 4d 69 78 20 26 20 69 6e 73 74 61 6c 6c 4d 70 34 42 65 66 6f 72 65 } //01 00 
		$a_01_2 = {2e 72 75 6e 20 22 73 63 72 69 70 74 72 75 6e 6e 65 72 20 2d 61 70 70 76 73 63 72 69 70 74 20 22 20 26 20 69 6e 73 74 61 6c 6c 4d 69 78 4d 69 78 2c 20 32 } //00 00 
	condition:
		any of ($a_*)
 
}