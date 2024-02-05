
rule Trojan_BAT_AgentTesla_OXCJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OXCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {04 14 0d de 4c 08 28 90 01 04 0b de 0a 08 2c 06 08 6f 90 01 04 dc 03 06 28 90 01 04 13 04 11 04 2c 17 18 2c 12 11 04 28 90 01 04 13 05 07 11 05 28 90 01 04 0d de 15 de 0c 11 04 2c 07 11 04 6f 90 01 04 dc 07 28 90 01 04 2a 90 00 } //01 00 
		$a_80_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 50 72 6f 70 65 72 74 69 65 73 } //WindowsFormsApp1.Properties  01 00 
		$a_80_2 = {53 6c 65 65 70 } //Sleep  01 00 
		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  00 00 
	condition:
		any of ($a_*)
 
}