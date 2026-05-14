
rule Trojan_BAT_AgentTesla_AWOB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AWOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 09 08 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 13 07 12 06 28 ?? 00 00 0a 13 08 12 06 28 ?? 00 00 0a 13 09 11 07 20 f0 00 00 00 5f 11 07 1f 0f 5f 60 d2 13 07 11 08 20 ff 00 00 00 5f d2 13 08 11 09 16 60 20 ff 00 00 00 5f d2 13 09 07 11 07 6f ?? 00 00 06 00 07 11 08 6f ?? 00 00 06 00 07 11 09 6f ?? 00 00 06 00 07 06 12 04 6f ?? 00 00 06 00 11 04 16 fe 02 16 fe 01 13 14 11 14 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}