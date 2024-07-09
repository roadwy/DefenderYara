
rule Trojan_BAT_AgentTesla_PTHA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 12 02 28 ?? 00 00 0a 6f 04 00 00 0a 6f 05 00 00 0a 28 ?? 00 00 0a 07 28 ?? 00 00 0a 39 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}