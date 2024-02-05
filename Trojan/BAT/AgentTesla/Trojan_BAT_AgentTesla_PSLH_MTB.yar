
rule Trojan_BAT_AgentTesla_PSLH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSLH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 8e 2d 06 17 28 0f 00 00 0a 02 16 9a 28 02 00 00 06 28 03 00 00 06 28 10 00 00 0a 28 11 00 00 0a 26 2a } //00 00 
	condition:
		any of ($a_*)
 
}