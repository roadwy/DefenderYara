
rule Trojan_BAT_AgentTesla_PTJX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 02 00 00 0a 72 01 00 00 70 28 90 01 01 00 00 0a 0a 06 28 90 01 01 00 00 0a 02 06 28 90 01 01 00 00 0a 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}