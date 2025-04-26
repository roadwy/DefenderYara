
rule Trojan_BAT_AgentTesla_FAV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 da 13 06 16 13 07 2b 23 07 08 06 11 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 08 17 d6 0c 11 07 18 d6 13 07 11 07 11 06 31 d7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}