
rule Trojan_BAT_AgentTesla_MBJU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 04 61 05 59 20 00 01 00 00 58 0a 2b 00 } //1
		$a_01_1 = {13 06 03 07 11 06 20 00 01 00 00 5d d2 9c 00 06 17 59 0a } //1
		$a_01_2 = {38 00 46 00 35 00 59 00 34 00 46 00 46 00 37 00 48 00 35 00 32 00 35 00 46 00 44 00 5a 00 53 00 35 00 47 00 37 00 34 00 34 00 44 00 } //1 8F5Y4FF7H525FDZS5G744D
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}