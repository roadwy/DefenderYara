
rule Trojan_BAT_AgentTesla_MBHW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 07 17 58 06 8e 69 5d 91 13 09 11 07 11 08 61 11 09 20 00 01 00 00 58 20 00 01 00 00 5d 59 13 0a 06 08 11 0a d2 9c 07 17 59 } //00 00 
	condition:
		any of ($a_*)
 
}