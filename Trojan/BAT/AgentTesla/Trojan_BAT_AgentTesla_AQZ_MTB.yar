
rule Trojan_BAT_AgentTesla_AQZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {17 da 13 06 16 13 07 2b 21 07 11 04 11 07 90 01 05 13 08 11 08 90 01 05 13 09 08 06 11 09 b4 9c 11 07 17 d6 13 07 11 07 11 06 31 d9 06 17 d6 0a 11 04 17 d6 13 04 11 04 09 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}