
rule Trojan_BAT_AgentTesla_AAJJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 11 04 08 8e 69 5d 08 11 04 08 8e 69 5d 91 09 11 04 1f 16 5d 6f 90 01 01 00 00 0a 61 08 11 04 17 58 08 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 11 04 15 58 13 04 00 11 04 16 fe 04 16 fe 01 13 07 11 07 2d b6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}