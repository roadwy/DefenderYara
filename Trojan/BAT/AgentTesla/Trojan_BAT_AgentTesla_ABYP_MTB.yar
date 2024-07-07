
rule Trojan_BAT_AgentTesla_ABYP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABYP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 31 00 11 05 09 5d 13 16 11 05 09 5b 13 17 08 11 16 11 17 6f 90 01 01 00 00 0a 13 18 07 11 06 12 18 28 90 01 01 00 00 0a 9c 11 06 17 58 13 06 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 19 11 19 2d c1 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}