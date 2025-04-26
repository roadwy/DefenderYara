
rule Trojan_BAT_AgentTesla_PSRG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 02 00 00 0a 28 14 00 00 06 6f 03 00 00 0a 28 04 00 00 0a 28 0f 00 00 06 1a 2d 03 26 de 06 0a 2b fb 26 de 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}