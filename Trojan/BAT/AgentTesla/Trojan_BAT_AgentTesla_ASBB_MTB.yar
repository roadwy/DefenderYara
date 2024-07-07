
rule Trojan_BAT_AgentTesla_ASBB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 16 06 7b 90 01 01 0a 00 04 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 7e 90 01 01 0a 00 04 25 3a 90 01 01 00 00 00 26 7e 90 01 01 0a 00 04 fe 06 90 01 01 12 00 06 73 90 01 01 00 00 0a 25 80 90 01 01 0a 00 04 28 90 01 01 00 00 2b 06 fe 06 90 01 01 12 00 06 73 90 01 01 00 00 0a 28 90 01 01 00 00 2b 28 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}