
rule Trojan_BAT_AgentTesla_OXCJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OXCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {04 14 0d de 4c 08 28 ?? ?? ?? ?? 0b de 0a 08 2c 06 08 6f ?? ?? ?? ?? dc 03 06 28 ?? ?? ?? ?? 13 04 11 04 2c 17 18 2c 12 11 04 28 ?? ?? ?? ?? 13 05 07 11 05 28 ?? ?? ?? ?? 0d de 15 de 0c 11 04 2c 07 11 04 6f ?? ?? ?? ?? dc 07 28 ?? ?? ?? ?? 2a } //10
		$a_80_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 50 72 6f 70 65 72 74 69 65 73 } //WindowsFormsApp1.Properties  1
		$a_80_2 = {53 6c 65 65 70 } //Sleep  1
		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}