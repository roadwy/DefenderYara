
rule Trojan_O97M_Obfuse_AS{
	meta:
		description = "Trojan:O97M/Obfuse.AS,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 73 45 72 72 6f 72 20 43 56 45 72 72 28 } //01 00 
		$a_01_1 = {22 63 6d 64 2e 65 78 65 20 2f 63 20 50 5e 22 20 2b 20 90 02 10 43 68 72 90 05 01 01 57 28 } //00 00 
	condition:
		any of ($a_*)
 
}