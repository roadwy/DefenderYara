
rule Trojan_BAT_AgentTesla_ADC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {25 16 08 a2 25 17 19 8d 90 02 04 25 16 7e 90 02 04 a2 25 17 7e 90 02 04 a2 25 18 90 02 0a a2 a2 25 0d 14 14 18 8d 90 02 04 25 16 17 9c 25 13 04 17 28 90 02 04 26 90 00 } //02 00 
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  02 00 
		$a_80_2 = {47 65 74 54 79 70 65 73 } //GetTypes  02 00 
		$a_80_3 = {41 63 74 69 76 61 74 6f 72 } //Activator  02 00 
		$a_80_4 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //GetObjectValue  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ADC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 41 32 33 35 34 38 00 } //01 00  䄀㌲㐵8
		$a_01_1 = {00 41 36 38 37 39 00 } //01 00 
		$a_01_2 = {00 41 41 41 31 32 33 00 } //01 00  䄀䅁㈱3
		$a_01_3 = {00 41 41 41 41 34 33 00 } //01 00  䄀䅁㑁3
		$a_01_4 = {00 44 44 44 44 44 44 44 44 44 44 44 34 34 00 } //01 00 
		$a_01_5 = {00 58 58 58 58 58 32 32 32 32 00 } //01 00 
		$a_01_6 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_01_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_8 = {54 6f 44 6f 75 62 6c 65 } //01 00  ToDouble
		$a_01_9 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}