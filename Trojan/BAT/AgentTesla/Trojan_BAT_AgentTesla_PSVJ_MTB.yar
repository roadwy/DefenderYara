
rule Trojan_BAT_AgentTesla_PSVJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 11 08 28 ?? 00 00 06 11 08 28 ?? 00 00 06 6f ?? 00 00 0a 13 09 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}