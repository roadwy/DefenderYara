
rule Trojan_BAT_AgentTesla_PSMC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 a2 25 1b 72 37 0b 00 70 a2 28 90 01 03 0a 13 06 11 06 72 83 0a 00 70 28 90 01 03 0a 13 06 11 06 72 79 0b 00 70 28 90 01 03 0a 13 06 11 06 72 c5 0b 00 70 28 90 01 03 0a 13 06 72 fd 0b 00 70 11 06 28 90 01 03 0a 72 fd 0b 00 70 28 90 01 03 0a 26 de 45 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}