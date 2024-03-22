
rule Trojan_BAT_AgentTesla_RDAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 03 28 74 00 00 0a 20 1b } //02 00 
		$a_01_1 = {11 03 28 75 00 00 0a 13 05 } //00 00 
	condition:
		any of ($a_*)
 
}