
rule Trojan_BAT_AgentTesla_JE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 8e 69 8d ?? 00 00 01 0b 16 0c 2b } //2
		$a_01_1 = {07 08 06 08 91 03 66 5f 06 08 91 66 03 5f 60 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}