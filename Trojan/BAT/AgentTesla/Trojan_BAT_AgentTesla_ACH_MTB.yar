
rule Trojan_BAT_AgentTesla_ACH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ACH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 16 94 11 04 17 94 6f ?? 00 00 0a 13 0d 11 04 16 94 1f 64 5d 2d 28 11 0a 72 ?? ?? 00 70 12 0d 28 ?? 00 00 0a 12 0d 28 ?? 00 00 0a 58 12 0d 28 ?? 00 00 0a 58 18 5d 16 fe 01 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}