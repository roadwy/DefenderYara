
rule Trojan_BAT_AgentTesla_AIK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 40 02 00 04 07 9a 06 28 9e 00 00 0a 39 0b 00 00 00 7e 41 02 00 04 74 23 00 00 01 2a 07 17 58 0b 07 7e 40 02 00 04 8e 69 3f d2 ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_AIK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 45 02 00 04 07 9a 06 28 a0 00 00 0a 39 0b 00 00 00 7e 46 02 00 04 74 25 00 00 01 2a 07 17 58 0b 07 7e 45 02 00 04 8e 69 3f d2 ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_AIK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 91 13 0b 06 17 58 09 5d 13 0c 07 06 91 11 0b 61 07 11 0c 91 59 13 0d 11 0d 20 00 01 00 00 58 13 0e 07 06 11 0e d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 0f 11 0f 2d ac } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}