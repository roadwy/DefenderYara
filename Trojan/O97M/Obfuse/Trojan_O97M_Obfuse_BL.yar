
rule Trojan_O97M_Obfuse_BL{
	meta:
		description = "Trojan:O97M/Obfuse.BL,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 65 74 20 90 02 20 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 40 29 29 0d 0a 20 20 20 20 45 6c 73 65 0d 0a 20 20 20 20 20 20 20 20 53 65 74 20 90 02 20 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 40 29 29 0d 0a 20 20 20 20 45 6e 64 20 49 66 90 00 } //01 00 
		$a_02_1 = {20 43 68 72 28 41 73 63 28 4d 69 64 28 90 02 40 2c 20 31 29 29 20 2d 90 00 } //01 00 
		$a_02_2 = {2e 52 75 6e 20 90 02 20 2c 20 90 02 20 2c 20 54 72 75 65 0d 0a 20 20 20 20 45 6e 64 20 49 66 90 00 } //01 00 
		$a_02_3 = {46 75 6e 63 74 69 6f 6e 20 90 02 20 28 29 0d 0a 20 20 20 20 53 65 6c 65 63 74 69 6f 6e 2e 57 68 6f 6c 65 53 74 6f 72 79 0d 0a 20 20 20 20 53 65 6c 65 63 74 69 6f 6e 2e 46 6f 6e 74 2e 43 6f 6c 6f 72 20 3d 20 2d 90 01 09 0d 0a 20 20 20 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 28 30 2c 20 30 29 2e 53 65 6c 65 63 74 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_02_4 = {57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 90 02 40 3d 20 2e 43 6f 75 6e 74 20 54 6f 20 31 20 53 74 65 70 20 2d 31 90 02 15 2e 49 74 65 6d 28 90 02 20 29 2e 44 65 6c 65 74 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}