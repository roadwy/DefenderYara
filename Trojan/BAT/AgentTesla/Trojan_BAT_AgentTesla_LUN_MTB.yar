
rule Trojan_BAT_AgentTesla_LUN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LUN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 2a 00 08 09 11 04 28 90 01 03 06 13 08 11 08 28 90 01 03 0a 13 09 17 13 0a 07 09 11 09 d2 6f 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 0b 11 0b 2d cb 06 17 58 0a 00 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}