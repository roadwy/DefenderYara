
rule Trojan_BAT_AgentTesla_MBAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d d9 90 00 } //01 00 
		$a_03_1 = {08 07 11 07 9a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}