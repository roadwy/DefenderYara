
rule Trojan_BAT_AgentTesla_PSZR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {3a e9 03 00 00 28 ?? 00 00 0a 13 2a 28 ?? 00 00 0a 13 2b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}