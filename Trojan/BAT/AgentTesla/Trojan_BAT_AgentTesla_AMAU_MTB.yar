
rule Trojan_BAT_AgentTesla_AMAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 18 6f 90 01 01 00 00 0a 00 07 18 6f 90 01 01 00 00 0a 00 07 06 6f 90 01 01 00 00 0a 00 02 07 28 90 01 01 00 00 06 00 2a 90 00 } //05 00 
		$a_03_1 = {04 8e 69 0b 02 06 07 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 07 8c 90 01 01 00 00 01 14 6f 90 01 01 00 00 0a 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}