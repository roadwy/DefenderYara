
rule Trojan_BAT_AgentTesla_PTHA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 12 02 28 90 01 01 00 00 0a 6f 04 00 00 0a 6f 05 00 00 0a 28 90 01 01 00 00 0a 07 28 90 01 01 00 00 0a 39 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}