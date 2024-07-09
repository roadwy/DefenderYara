
rule Trojan_BAT_AgentTesla_PTIN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 40 12 08 28 ?? 00 00 06 00 08 28 ?? 00 00 2b 16 11 06 08 8e 69 28 ?? 00 00 0a 00 11 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}