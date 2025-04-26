
rule Trojan_BAT_AgentTesla_ABXT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 3f 00 16 13 05 2b 22 00 07 11 04 11 05 28 ?? 00 00 06 13 06 08 12 06 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 11 05 17 58 13 05 11 05 07 28 ?? 00 00 06 fe 04 13 07 11 07 2d ce 00 11 04 17 58 13 04 11 04 07 28 ?? 00 00 06 fe 04 13 08 11 08 2d b1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}