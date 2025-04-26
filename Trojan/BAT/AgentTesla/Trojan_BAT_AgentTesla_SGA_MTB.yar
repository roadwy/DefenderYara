
rule Trojan_BAT_AgentTesla_SGA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 28 07 00 00 0a 6f 08 00 00 0a 28 09 00 00 0a 11 06 16 16 6f 0b 00 00 06 16 26 26 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}