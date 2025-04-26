
rule Trojan_BAT_AgentTesla_MBEP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 ?? 00 00 0a 0c 08 07 7e ?? 02 00 04 28 ?? 03 00 06 00 03 07 7e ?? 02 00 04 } //1
		$a_01_1 = {32 33 32 61 32 35 65 66 62 39 34 37 } //1 232a25efb947
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_MBEP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 07 5d 13 09 07 11 0c 5d 13 0f 07 17 58 11 07 5d 13 10 11 04 11 09 91 13 11 20 00 01 00 00 13 0a 11 11 11 08 11 0f 91 61 11 04 11 10 91 59 11 0a 58 11 0a 5d 13 12 11 04 11 09 11 12 d2 9c 07 17 58 0b 07 11 07 11 0b 17 58 5a fe 04 13 13 11 13 2d ac } //1
		$a_01_1 = {06 08 5d 13 05 06 11 08 5d 13 0b 06 17 58 08 5d 13 0c 07 11 05 91 13 0d 20 00 01 00 00 13 06 11 0d 11 04 11 0b 91 61 07 11 0c 91 59 11 06 58 11 06 5d 13 0e 07 11 05 11 0e d2 9c 06 17 58 0a 06 08 11 07 17 58 5a 32 b8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}