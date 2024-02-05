
rule Trojan_BAT_AgentTesla_JLA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 11 05 72 90 01 03 70 28 90 01 03 0a 72 90 01 03 70 20 90 01 03 00 14 14 18 8d 90 01 03 01 25 16 07 11 05 18 d8 18 6f 90 01 03 0a a2 25 17 1f 10 8c 90 01 03 01 a2 6f 90 01 03 0a 28 90 01 03 0a 9c 11 05 17 d6 13 05 11 05 11 04 31 b2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}