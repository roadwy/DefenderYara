
rule Trojan_BAT_AgentTesla_PSXK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 06 11 04 6f 90 01 01 00 00 0a 73 08 00 00 06 11 04 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 de 2e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}