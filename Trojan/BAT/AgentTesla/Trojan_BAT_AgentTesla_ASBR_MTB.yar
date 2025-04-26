
rule Trojan_BAT_AgentTesla_ASBR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 08 2b 3a 16 13 09 2b 2a 09 11 04 11 08 58 11 07 11 09 58 6f ?? 00 00 0a 13 0a 12 0a 28 ?? 00 00 0a 13 0b 08 07 11 0b 9c 07 17 58 0b 11 09 17 58 13 09 11 09 17 32 d1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}