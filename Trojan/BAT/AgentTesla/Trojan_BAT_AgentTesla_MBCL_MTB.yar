
rule Trojan_BAT_AgentTesla_MBCL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 11 09 17 7e ?? 00 00 0a a2 11 09 18 11 06 72 de 07 00 70 6f ?? 00 00 0a a2 11 09 13 0a 11 0a 13 0b 1f 1a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_MBCL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 06 72 0f 01 00 70 6f ?? 00 00 0a 74 ?? 00 00 01 28 ?? 00 00 06 28 ?? 00 00 06 17 8d ?? 00 00 01 25 16 1f 3d 9d 6f ?? 00 00 0a 0b 20 00 2c 01 00 8d ?? 00 00 01 0c 16 13 04 2b 17 00 08 11 04 07 11 04 9a } //1
		$a_01_1 = {33 2d 35 35 64 64 34 62 62 63 64 32 36 39 } //1 3-55dd4bbcd269
		$a_01_2 = {45 00 67 00 2e 00 43 00 70 00 } //1 Eg.Cp
		$a_01_3 = {4d 30 4d 30 4d 30 4d 30 4d 30 4d 30 4d 30 4d 30 4d 30 4d 30 4d 30 4d 30 4d 30 4d 30 4d } //1 M0M0M0M0M0M0M0M0M0M0M0M0M0M0M
		$a_01_4 = {55 6d 64 50 61 72 73 65 72 2e 50 72 6f } //1 UmdParser.Pro
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}