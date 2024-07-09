
rule Trojan_BAT_AgentTesla_PSZV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 bf fe ff ff 11 02 28 ?? 00 00 06 13 06 20 07 00 00 00 38 ac fe ff ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}