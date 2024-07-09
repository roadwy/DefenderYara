
rule Trojan_BAT_AgentTesla_ABYQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABYQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 2a 07 11 04 5d 13 09 07 11 04 5b 13 0a 09 11 09 11 0a 6f ?? 00 00 0a 13 0d 11 05 12 0d 28 ?? 00 00 0a 6f ?? 00 00 0a 07 17 58 0b 07 11 04 11 06 5a fe 04 13 0b 11 0b 2d c8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}