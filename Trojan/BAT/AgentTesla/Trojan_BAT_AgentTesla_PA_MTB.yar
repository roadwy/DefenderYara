
rule Trojan_BAT_AgentTesla_PA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {13 04 11 04 1f 61 32 0b 11 04 1f 7a fe 02 16 fe 01 2b 01 16 13 05 11 05 2c 24 00 11 04 1f 0d 58 13 06 11 06 1f 7a fe 02 13 07 11 07 2c 07 11 06 1f 1a 59 13 06 06 09 11 06 d1 9d 00 2b } //1
		$a_02_1 = {11 04 1f 41 32 0b 11 04 1f 5a fe 02 16 fe 01 2b 01 16 13 08 11 08 2c 24 00 11 04 1f 0d 58 13 09 11 09 1f 5a fe 02 13 0a 11 0a 2c 07 11 09 1f 1a 59 13 09 06 09 11 09 d1 9d 00 2b 07 00 06 09 11 04 9d 00 00 09 17 58 0d 09 02 6f ?? 00 00 0a fe 04 13 0b 11 0b 3a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_PA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.PA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 3a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}