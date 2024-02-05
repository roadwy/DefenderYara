
rule Trojan_BAT_AgentTesla_ANOT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ANOT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 05 06 11 04 11 05 a2 07 11 05 11 04 d2 6f 90 01 03 0a 07 11 05 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}