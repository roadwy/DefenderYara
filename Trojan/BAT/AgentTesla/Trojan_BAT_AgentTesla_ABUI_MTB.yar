
rule Trojan_BAT_AgentTesla_ABUI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABUI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 20 00 07 09 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 13 05 08 11 05 6f 90 01 01 00 00 0a 00 09 18 58 0d 00 09 07 6f 90 01 01 00 00 0a fe 04 13 06 11 06 2d d1 28 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}