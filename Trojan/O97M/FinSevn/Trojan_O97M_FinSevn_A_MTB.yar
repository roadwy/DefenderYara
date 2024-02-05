
rule Trojan_O97M_FinSevn_A_MTB{
	meta:
		description = "Trojan:O97M/FinSevn.A!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 73 67 42 6f 78 20 28 22 44 6f 63 75 6d 65 6e 74 20 64 65 63 72 79 70 74 20 65 72 72 6f 72 2e 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}