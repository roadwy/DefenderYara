
rule Trojan_BAT_AgentTesla_PSNQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {38 12 00 00 00 00 28 04 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c eb 28 02 00 00 0a 06 6f 03 00 00 0a 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}