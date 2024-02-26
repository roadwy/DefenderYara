
rule Trojan_BAT_AgentTesla_ASEP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 04 11 08 58 17 58 17 59 11 07 11 09 58 17 58 17 59 6f 90 01 01 00 00 0a 13 0a 12 0a 28 90 01 01 00 00 0a 13 0b 08 07 11 0b 9c 07 17 58 0b 11 09 17 58 13 09 00 11 09 17 fe 04 13 0c 11 0c 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}