
rule Trojan_BAT_AgentTesla_PSYG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 20 8c 0f c1 05 28 ?? 00 00 06 28 ?? 00 00 06 20 ab 0f c1 05 28 ?? 00 00 06 28 ?? 00 00 0a 6f 35 00 00 0a 13 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}