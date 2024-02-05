
rule Trojan_BAT_AgentTesla_NEG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 9a 13 04 06 07 11 04 1d 28 90 01 01 00 00 0a 9c 07 17 58 0b 09 17 58 0d 09 08 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}