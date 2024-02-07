
rule Trojan_O97M_Obfuse_BI{
	meta:
		description = "Trojan:O97M/Obfuse.BI,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {0d 0a 53 68 65 6c 6c 20 } //01 00 
		$a_00_1 = {20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 22 20 26 20 22 22 20 26 20 22 6d 70 22 29 } //01 00   = Environ("Te" & "" & "mp")
		$a_02_2 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 20 20 26 20 22 73 63 72 69 70 74 69 6e 67 22 20 26 20 22 2e 66 69 6c 65 73 79 73 74 22 20 26 20 22 65 6d 6f 62 6a 65 63 74 22 29 90 00 } //01 00 
		$a_02_3 = {3d 20 45 6e 76 69 72 6f 6e 28 90 02 20 20 26 20 22 73 79 73 74 65 6d 72 6f 6f 74 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}