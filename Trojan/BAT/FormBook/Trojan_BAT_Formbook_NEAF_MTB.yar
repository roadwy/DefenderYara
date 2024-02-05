
rule Trojan_BAT_Formbook_NEAF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NEAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {02 7b 94 00 00 04 7b f2 00 00 04 7e eb 00 00 04 20 0a 01 00 00 7e eb 00 00 04 20 0a 01 00 00 91 7e 48 00 00 04 20 b5 01 00 00 94 61 20 da 00 00 00 5f 9c 2a } //02 00 
		$a_01_1 = {62 2e 52 2e 72 65 73 6f 75 72 63 65 73 } //02 00 
		$a_01_2 = {31 35 34 61 31 65 32 34 66 32 33 34 66 36 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}