
rule Trojan_BAT_AgentTesla_GAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 07 8e 69 17 da 13 06 16 13 07 2b 18 08 07 11 07 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 07 17 d6 13 07 11 07 11 06 31 e2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}