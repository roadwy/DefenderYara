
rule Trojan_BAT_AgentTesla_PSXU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 00 72 37 00 00 70 28 90 01 01 00 00 06 72 69 00 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 13 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}