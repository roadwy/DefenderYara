
rule Trojan_BAT_AgentTesla_ABZE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 28 06 09 5d 13 08 06 09 5b 13 09 08 11 08 11 09 6f ?? 00 00 0a 13 0c 11 05 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 06 17 58 0a 06 09 11 06 5a fe 04 13 0a 11 0a 2d cb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}