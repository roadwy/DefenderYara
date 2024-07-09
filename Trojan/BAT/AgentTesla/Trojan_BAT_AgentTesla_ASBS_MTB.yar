
rule Trojan_BAT_AgentTesla_ASBS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 1f 10 da 17 da 17 d6 8d ?? 00 00 01 0a 02 1f 10 06 16 06 8e 69 28 ?? 00 00 0a 06 8e 69 17 da 0b 16 0c 2b 16 06 08 8f ?? 00 00 01 25 47 02 08 1f 10 5d 91 61 d2 52 08 17 d6 0c 08 07 fe 02 16 fe 01 0d 09 2d df } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}