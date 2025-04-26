
rule Trojan_BAT_AgentTesla_RDCE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 0e 00 00 0a 02 28 0b 00 00 0a 75 01 00 00 1b 6f 0f 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}