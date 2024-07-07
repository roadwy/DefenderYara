
rule Trojan_BAT_AgentTesla_DRP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 23 00 09 11 04 11 05 28 90 01 03 06 13 08 11 08 28 90 01 03 0a 13 09 08 07 11 09 d2 9c 00 11 05 17 58 13 05 11 05 17 fe 04 13 0a 11 0a 2d d2 07 17 58 0b 00 11 04 17 58 13 04 90 00 } //1
		$a_01_1 = {00 45 58 30 30 30 30 32 00 } //1
		$a_01_2 = {00 45 58 30 30 30 30 31 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}