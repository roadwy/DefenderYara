
rule Trojan_BAT_PredatorPainRAT_A_MTB{
	meta:
		description = "Trojan:BAT/PredatorPainRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 04 06 1a 58 91 06 28 90 01 01 00 00 06 61 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}