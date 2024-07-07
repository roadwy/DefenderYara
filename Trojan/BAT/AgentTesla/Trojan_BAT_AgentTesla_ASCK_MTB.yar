
rule Trojan_BAT_AgentTesla_ASCK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 16 13 09 2b 25 00 11 04 11 09 18 6f 90 01 01 00 00 0a 13 0a 11 05 11 09 18 5b 11 0a 1f 10 28 90 01 01 00 00 0a d2 9c 00 11 09 18 58 13 09 11 09 11 04 6f 90 01 01 00 00 0a fe 04 13 0b 11 0b 2d ca 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}