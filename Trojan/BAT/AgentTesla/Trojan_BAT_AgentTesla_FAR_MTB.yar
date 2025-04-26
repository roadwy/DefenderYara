
rule Trojan_BAT_AgentTesla_FAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 13 00 38 00 00 00 00 28 ?? 00 00 0a 11 00 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 13 01 38 00 00 00 00 dd ?? 00 00 00 26 38 00 00 00 00 dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}