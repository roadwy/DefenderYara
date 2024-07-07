
rule Trojan_BAT_AgentTesla_ABXJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABXJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 43 00 16 13 04 2b 28 00 08 09 11 04 6f 90 01 01 00 00 0a 13 0f 12 0f 28 90 01 01 00 00 0a 13 10 07 11 05 11 10 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f 90 01 01 00 00 0a fe 04 13 11 11 11 2d c8 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}