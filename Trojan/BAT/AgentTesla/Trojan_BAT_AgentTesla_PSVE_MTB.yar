
rule Trojan_BAT_AgentTesla_PSVE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 20 01 00 00 00 38 c0 ff ff ff 11 07 11 07 28 ?? 00 00 06 11 07 28 ?? 00 00 06 6f ?? 00 00 0a 13 01 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}