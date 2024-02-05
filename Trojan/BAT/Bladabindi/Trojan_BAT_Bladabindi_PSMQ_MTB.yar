
rule Trojan_BAT_Bladabindi_PSMQ_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PSMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {2b 22 28 18 00 00 0a 02 6f 19 00 00 0a 0a 06 28 1a 00 00 0a 0b 08 20 c4 43 a6 58 5a 20 33 24 e4 8e 61 2b c1 } //00 00 
	condition:
		any of ($a_*)
 
}