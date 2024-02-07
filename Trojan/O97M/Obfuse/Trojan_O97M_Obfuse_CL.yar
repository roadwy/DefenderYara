
rule Trojan_O97M_Obfuse_CL{
	meta:
		description = "Trojan:O97M/Obfuse.CL,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 90 02 10 22 2c 20 90 00 } //01 00 
		$a_03_1 = {20 2b 20 53 68 65 6c 6c 28 90 02 10 20 2b 20 90 02 10 20 2b 20 90 02 10 2c 20 90 02 10 20 2d 20 90 02 10 29 20 2b 20 90 00 } //01 00 
		$a_01_2 = {6f 77 65 22 20 2b 20 22 72 73 22 } //01 00  owe" + "rs"
		$a_01_3 = {22 68 65 6c 6c 22 20 2b 20 22 20 20 22 20 } //00 00  "hell" + "  " 
	condition:
		any of ($a_*)
 
}