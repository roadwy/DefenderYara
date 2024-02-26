
rule Trojan_BAT_AgentTesla_RDAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 16 02 8e 69 6f 2a 00 00 0a 0b } //00 00 
	condition:
		any of ($a_*)
 
}