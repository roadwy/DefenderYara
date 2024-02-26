
rule Trojan_BAT_AgentTesla_PTHQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 09 6f d8 00 00 0a 28 0c 00 00 2b 13 07 } //00 00 
	condition:
		any of ($a_*)
 
}