
rule Trojan_BAT_AgentTesla_AZK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 0b 72 01 00 00 70 2b 07 2b 0c de 1a 07 2b f2 6f 0f 00 00 0a 2b f2 0a 2b f1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}