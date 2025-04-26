
rule Trojan_BAT_AgentTesla_PMUH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PMUH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 16 13 05 38 1d 00 00 00 11 04 09 11 05 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 18 58 13 05 11 05 09 6f ?? 00 00 0a 32 d9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}