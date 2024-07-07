
rule Trojan_BAT_AgentTesla_MBGO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 20 00 01 00 00 6f 90 01 01 00 00 0a 06 7e 01 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 7e 02 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 06 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 14 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_MBGO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 2b 29 11 07 06 08 58 07 09 58 6f 90 01 01 00 00 0a 13 0f 12 0f 28 90 01 01 00 00 0a 13 09 11 06 11 04 11 09 9c 11 04 17 58 13 04 09 17 58 0d 09 17 fe 04 13 0a 11 0a 2d cd 90 00 } //1
		$a_03_1 = {16 13 04 20 00 ac 00 00 8d 90 01 01 00 00 01 13 06 11 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}