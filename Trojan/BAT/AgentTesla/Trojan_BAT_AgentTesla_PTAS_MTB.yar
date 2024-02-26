
rule Trojan_BAT_AgentTesla_PTAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 26 11 04 28 90 01 01 00 00 0a 6f 26 00 00 0a 13 37 18 13 07 11 07 16 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}