
rule Trojan_BAT_AgentTesla_PSVJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 08 11 08 28 90 01 01 00 00 06 11 08 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 13 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}