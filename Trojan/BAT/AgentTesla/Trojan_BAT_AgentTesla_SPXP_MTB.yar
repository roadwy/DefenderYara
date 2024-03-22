
rule Trojan_BAT_AgentTesla_SPXP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {5d d4 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a 9c 06 17 6a 58 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}