
rule Trojan_BAT_AgentTesla_MBEY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 05 09 08 6f 90 01 01 00 00 0a 13 11 16 13 04 11 06 07 9a 20 90 01 04 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 13 0b 11 0b 2c 0b 12 11 28 90 01 01 00 00 0a 13 04 2b 46 11 06 07 9a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}