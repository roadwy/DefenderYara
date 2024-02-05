
rule Trojan_O97M_Obfuse_BK{
	meta:
		description = "Trojan:O97M/Obfuse.BK,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {20 3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 40 20 26 20 43 68 72 28 41 73 63 28 4d 69 64 28 90 02 40 2c 20 31 29 29 20 2d 90 00 } //01 00 
		$a_02_1 = {20 3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 20 29 20 53 74 65 70 20 32 0d 0a 90 02 40 20 26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 90 02 30 2c 20 32 29 29 29 90 00 } //01 00 
		$a_02_2 = {57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 90 02 40 3d 20 2e 43 6f 75 6e 74 20 54 6f 20 31 20 53 74 65 70 20 2d 31 90 02 15 2e 49 74 65 6d 28 90 02 20 29 2e 44 65 6c 65 74 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}