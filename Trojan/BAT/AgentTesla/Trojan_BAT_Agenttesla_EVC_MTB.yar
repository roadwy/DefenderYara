
rule Trojan_BAT_Agenttesla_EVC_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.EVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 07 17 da 28 90 01 03 06 28 90 01 03 06 11 04 11 07 11 04 28 90 01 03 06 5d 28 90 01 03 06 28 90 01 03 06 da 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {53 00 74 00 72 00 69 00 6e 00 67 00 31 00 } //01 00 
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}