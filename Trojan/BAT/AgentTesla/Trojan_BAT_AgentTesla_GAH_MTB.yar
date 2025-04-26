
rule Trojan_BAT_AgentTesla_GAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 08 2b 2f 00 08 6f ?? 00 00 0a 11 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 28 ?? 00 00 0a 16 91 13 09 09 11 09 6f ?? 00 00 0a 00 00 11 08 18 58 13 08 11 08 08 6f ?? 00 00 0a 6f ?? 00 00 0a fe 04 13 0a 11 0a 2d bc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}