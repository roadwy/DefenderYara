
rule Trojan_BAT_AgentTesla_MBBB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 90 00 } //01 00 
		$a_01_1 = {38 30 30 34 2d 33 61 66 62 35 61 61 38 30 63 34 34 } //00 00 
	condition:
		any of ($a_*)
 
}