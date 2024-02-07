
rule Trojan_O97M_Obfuse_BC{
	meta:
		description = "Trojan:O97M/Obfuse.BC,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } //01 00  Private Sub Document_open()
		$a_02_1 = {0d 0a 43 6f 6e 73 74 20 90 02 20 20 3d 20 90 02 0f 20 2d 20 90 02 20 53 68 65 6c 6c 40 20 53 68 61 70 65 73 28 90 02 70 29 2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74 20 2b 20 90 12 0f 00 20 2b 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}