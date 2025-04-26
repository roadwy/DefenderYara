
rule Trojan_BAT_AgentTesla_MBEY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 09 08 6f ?? 00 00 0a 13 11 16 13 04 11 06 07 9a 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 0a 13 0b 11 0b 2c 0b 12 11 28 ?? 00 00 0a 13 04 2b 46 11 06 07 9a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_MBEY_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 0d 16 0a 2b 3f 06 09 5d 13 04 06 1f 16 5d 13 0b 06 17 58 09 5d 13 0c 07 11 04 91 13 0d 20 00 01 00 00 13 05 11 0d 11 06 11 0b 91 61 07 11 0c 91 59 11 05 58 11 05 5d 13 0e 07 11 04 11 0e d2 9c 06 17 58 0a 06 09 11 07 17 58 5a fe 04 13 0f 11 0f 2d b2 } //1
		$a_01_1 = {16 0a 2b 3f 06 08 5d 13 04 06 1f 16 5d 13 0a 06 17 58 08 5d 13 0b 07 11 04 91 13 0c 20 00 01 00 00 13 05 11 0c 11 06 11 0a 91 61 07 11 0b 91 59 11 05 58 11 05 5d 13 0d 07 11 04 11 0d d2 9c 06 17 58 0a 06 08 11 07 17 58 5a fe 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}