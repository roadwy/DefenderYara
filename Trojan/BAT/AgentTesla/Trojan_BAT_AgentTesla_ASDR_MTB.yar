
rule Trojan_BAT_AgentTesla_ASDR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 07 8e 69 17 da 13 07 16 13 08 2b 22 08 11 08 17 8d 90 01 01 00 00 01 25 16 07 11 08 9a 1f 10 28 90 01 01 00 00 0a 9c 6f 90 01 01 00 00 0a 11 08 17 d6 13 08 11 08 11 07 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}