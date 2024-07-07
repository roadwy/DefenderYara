
rule Trojan_BAT_AgentTesla_PSZK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 bf ff ff ff 28 90 01 01 00 00 06 75 01 00 00 1b 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 2a 19 8c 09 00 00 01 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}