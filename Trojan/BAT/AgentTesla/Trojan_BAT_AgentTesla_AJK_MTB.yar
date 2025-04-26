
rule Trojan_BAT_AgentTesla_AJK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 1a 5d 16 fe 01 0d 09 2c 0b 02 08 02 08 91 1f 3d 61 b4 9c 00 00 08 17 d6 0c 08 07 31 e2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_AJK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 08 03 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 04 8e 69 fe 04 0d 09 2d e1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}