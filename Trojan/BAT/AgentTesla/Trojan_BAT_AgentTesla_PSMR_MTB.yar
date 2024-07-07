
rule Trojan_BAT_AgentTesla_PSMR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 32 00 00 0a 06 28 07 00 00 06 6f 33 00 00 0a 25 28 34 00 00 0a 72 3f 00 00 70 28 02 00 00 06 28 08 00 00 06 de 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}