
rule Trojan_BAT_AgentTesla_MLR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MLR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {9a 0a 02 06 28 90 01 05 16 28 90 01 05 16 0b 2b 00 07 2a 90 09 15 00 28 90 01 13 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}