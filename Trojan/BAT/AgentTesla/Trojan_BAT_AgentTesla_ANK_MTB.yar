
rule Trojan_BAT_AgentTesla_ANK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ANK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 0d 91 13 0e 07 17 58 11 09 5d 13 0f 08 07 02 08 07 91 11 0e 61 08 11 0f 91 59 28 34 00 00 06 28 4b 00 00 0a 9c 07 17 58 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_ANK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ANK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 06 18 5b 8d 31 00 00 01 0b 16 0c 2b 18 07 08 18 5b 03 08 18 6f 32 00 00 0a 1f 10 28 33 00 00 0a 9c 08 18 58 0c 08 06 32 e4 } //1
		$a_01_1 = {2b 0a 20 d6 02 92 02 28 1d 00 00 0a 03 2d f3 17 28 2d 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}