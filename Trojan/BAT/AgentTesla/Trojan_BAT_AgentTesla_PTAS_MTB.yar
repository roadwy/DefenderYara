
rule Trojan_BAT_AgentTesla_PTAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 26 11 04 28 ?? 00 00 0a 6f 26 00 00 0a 13 37 18 13 07 11 07 16 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}