
rule Trojan_BAT_AgentTesla_LGE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 38 00 09 11 04 11 05 6f 90 01 03 0a 13 06 09 11 04 11 05 6f 90 01 03 0a 13 07 16 13 08 02 11 07 28 90 01 03 06 13 08 17 13 09 00 08 07 11 08 d2 9c 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 0a 11 0a 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}