
rule Trojan_O97M_Obfuse_DH{
	meta:
		description = "Trojan:O97M/Obfuse.DH,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {22 6e 6d 22 20 2b 20 22 67 6d 74 22 20 2b 20 90 02 10 20 2b 20 22 73 3a 57 69 22 20 2b 20 22 6e 33 32 5f 50 72 22 20 2b 20 22 6f 63 65 73 73 53 74 22 20 2b 20 22 61 72 74 75 70 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}