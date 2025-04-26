
rule Trojan_BAT_AgentTesla_PSZH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {75 10 00 00 01 28 ?? 00 00 06 28 ?? 00 00 2b 72 55 00 00 70 6f 0b 00 00 0a 14 14 28 ?? 00 00 06 74 13 00 00 01 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}