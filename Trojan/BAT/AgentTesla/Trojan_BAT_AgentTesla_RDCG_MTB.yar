
rule Trojan_BAT_AgentTesla_RDCG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0f 01 28 8a 00 00 0a 9c 25 17 0f 01 28 8b 00 00 0a 9c 25 18 0f 01 28 8c 00 00 0a 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}