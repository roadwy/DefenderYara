
rule Trojan_BAT_AgentTesla_KAAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {00 08 11 0a 18 6f 90 01 01 00 00 0a 13 0b 09 11 0a 18 5b 11 0b 1f 10 28 90 01 01 00 00 0a 9c 00 11 0a 18 58 13 0a 11 0a 08 6f 90 01 01 00 00 0a fe 04 13 0c 11 0c 2d ce 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}