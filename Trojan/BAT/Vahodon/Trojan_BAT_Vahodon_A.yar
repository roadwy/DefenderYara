
rule Trojan_BAT_Vahodon_A{
	meta:
		description = "Trojan:BAT/Vahodon.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 00 6e 00 66 00 6f 00 7c 00 7c 00 } //01 00 
		$a_01_1 = {53 65 6e 64 00 73 00 62 00 52 43 00 } //01 00 
		$a_01_2 = {00 53 42 00 42 53 00 } //00 00 
	condition:
		any of ($a_*)
 
}