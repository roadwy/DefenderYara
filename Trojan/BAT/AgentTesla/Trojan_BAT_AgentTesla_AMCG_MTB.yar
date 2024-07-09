
rule Trojan_BAT_AgentTesla_AMCG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 2c 23 06 6f ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 02 07 28 ?? 00 00 06 2a 73 ?? 00 00 0a 7a } //2
		$a_03_1 = {2a 5a 02 7b ?? 00 00 04 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}