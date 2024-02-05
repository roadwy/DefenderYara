
rule Trojan_BAT_AgentTesla_MBFJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 04 18 6f 90 01 01 00 00 0a 13 05 07 11 04 18 5b 11 05 1f 10 28 90 01 01 00 00 0a 9c 00 11 04 18 58 13 04 11 04 06 6f 90 01 01 00 00 0a fe 04 13 06 11 06 2d ce 90 00 } //01 00 
		$a_01_1 = {2a 00 33 00 2a 00 45 00 32 00 30 00 30 00 2a 00 33 00 2a 00 45 00 32 00 2a 00 33 00 33 00 2a 00 45 00 32 00 2a 00 32 00 33 00 2a 00 2a 00 2a 00 45 00 36 00 2a 00 46 00 36 00 2a 00 39 00 36 00 2a 00 33 00 37 00 2a 00 } //00 00 
	condition:
		any of ($a_*)
 
}