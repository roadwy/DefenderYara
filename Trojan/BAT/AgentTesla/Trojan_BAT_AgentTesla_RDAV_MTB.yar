
rule Trojan_BAT_AgentTesla_RDAV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {13 04 11 04 13 05 11 05 28 1b 00 00 0a 13 06 } //00 00 
	condition:
		any of ($a_*)
 
}