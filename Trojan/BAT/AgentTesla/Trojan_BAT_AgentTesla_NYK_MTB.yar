
rule Trojan_BAT_AgentTesla_NYK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 2c 00 00 0a 0a 73 2d 00 00 0a 0b 06 16 73 2e 00 00 0a 73 2f 00 00 0a 0c 08 07 6f 30 00 00 0a de 0a } //1
		$a_01_1 = {57 95 b6 21 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 38 00 00 00 0a 00 00 00 08 00 00 00 19 00 00 00 0d 00 00 00 39 00 00 00 20 00 00 00 01 00 00 00 05 00 00 00 01 00 00 00 02 00 00 00 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}