
rule Trojan_BAT_AgentTesla_ABZF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 2e 00 11 05 09 5d 13 09 11 05 09 5b 13 0a 08 11 09 11 0a 6f 90 01 01 00 00 0a 13 0b 07 12 0b 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0c 11 0c 2d c4 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}