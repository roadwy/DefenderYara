
rule Trojan_BAT_AgentTesla_MBBT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 04 17 8d 90 01 01 00 00 01 25 16 06 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 1f 10 28 90 01 03 0a 86 6f 90 01 01 00 00 0a 06 17 d6 0a 06 20 00 7c 00 00 fe 04 13 06 11 06 2d c4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}