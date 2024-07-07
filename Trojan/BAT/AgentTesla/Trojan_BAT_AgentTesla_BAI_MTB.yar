
rule Trojan_BAT_AgentTesla_BAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 2d 9d 6f 90 01 01 00 00 0a 0b 07 8e 69 8d 90 01 01 00 00 01 0c 16 0a 2b 12 08 06 07 06 9a 1f 10 28 90 01 01 00 00 0a d2 9c 06 17 58 0a 06 07 8e 69 fe 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_BAI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {70 18 18 8d 90 01 03 01 25 16 09 8c 90 01 03 01 a2 25 17 11 04 8c 90 01 03 01 a2 28 90 01 03 06 25 2d 0d 26 12 0b 90 01 06 11 0b 2b 05 90 01 05 13 09 11 09 28 90 01 03 06 13 0a 07 06 11 0a b4 9c 11 04 17 d6 13 04 11 04 11 08 31 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}