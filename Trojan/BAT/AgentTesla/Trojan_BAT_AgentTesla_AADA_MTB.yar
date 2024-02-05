
rule Trojan_BAT_AgentTesla_AADA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 2c 00 11 04 11 06 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 16 91 13 08 11 05 11 08 6f 90 01 01 00 00 0a 00 11 06 18 58 13 06 00 11 06 11 04 6f 90 01 01 00 00 0a fe 04 13 09 11 09 2d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}