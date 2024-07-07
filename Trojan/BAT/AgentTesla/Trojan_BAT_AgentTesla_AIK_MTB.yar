
rule Trojan_BAT_AgentTesla_AIK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 91 13 0b 06 17 58 09 5d 13 0c 07 06 91 11 0b 61 07 11 0c 91 59 13 0d 11 0d 20 00 01 00 00 58 13 0e 07 06 11 0e d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 0f 11 0f 2d ac } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}