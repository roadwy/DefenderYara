
rule Trojan_BAT_AgentTesla_ABXD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 44 00 16 13 05 2b 27 00 07 11 04 11 05 6f 90 01 01 00 00 0a 13 06 08 12 06 28 90 01 01 00 00 0a 8c 90 01 01 00 00 01 6f 90 01 01 00 00 0a 26 00 11 05 17 58 13 05 11 05 07 6f 90 01 01 00 00 0a fe 04 13 07 11 07 2d c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}