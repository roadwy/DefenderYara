
rule Trojan_BAT_AgentTesla_FAP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 da 13 06 16 13 07 2b 1e 08 07 11 07 18 6f ?? 01 00 0a 1f 10 28 ?? 01 00 0a b4 6f ?? 01 00 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}