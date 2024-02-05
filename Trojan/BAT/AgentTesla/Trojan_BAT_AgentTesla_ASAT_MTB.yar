
rule Trojan_BAT_AgentTesla_ASAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0c 16 0a 2b 36 08 13 04 16 13 06 11 04 12 06 28 90 01 01 00 00 0a 08 09 06 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a de 0c 11 06 2c 07 11 04 28 90 01 01 00 00 0a dc 06 18 58 0a 06 09 6f 90 01 01 00 00 0a fe 04 13 07 11 07 2d bb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}