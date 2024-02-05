
rule Trojan_BAT_AgentTesla_MBHC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 50 00 16 13 05 2b 2f 00 07 11 04 11 05 6f 90 01 01 00 00 0a 13 09 07 11 04 11 05 6f 90 01 01 00 00 0a 13 0a 11 0a 28 90 01 01 00 00 0a 13 0b 09 08 11 0b d2 9c 00 11 05 17 58 13 05 11 05 07 6f 35 00 00 0a fe 04 13 0c 11 0c 2d c1 90 00 } //01 00 
		$a_01_1 = {16 0c 20 00 ba 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}