
rule Trojan_BAT_AgentTesla_PSZL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 bf ff ff ff 28 ?? 00 00 06 75 01 00 00 1b 28 ?? 00 00 06 28 ?? 00 00 06 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}