
rule Trojan_BAT_AgentTesla_NLR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NLR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 18 d2 13 2e 11 18 1e 63 d1 13 18 11 1a 11 0a 91 13 25 11 1a 11 0a 11 23 ?? ?? 61 19 11 1d 58 61 11 2e 61 d2 9c 11 25 13 1d 17 11 0a 58 ?? ?? 11 0a 11 26 32 a4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}