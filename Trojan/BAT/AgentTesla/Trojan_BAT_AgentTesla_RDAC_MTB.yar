
rule Trojan_BAT_AgentTesla_RDAC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 01 6f 1a 00 00 0a 13 02 } //2
		$a_01_1 = {11 06 28 13 00 00 0a 13 05 20 01 } //2
		$a_01_2 = {11 00 28 16 00 00 0a 74 1b 00 00 01 13 01 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}