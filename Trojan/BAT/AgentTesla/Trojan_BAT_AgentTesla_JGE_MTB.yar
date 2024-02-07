
rule Trojan_BAT_AgentTesla_JGE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {36 36 38 34 30 44 44 41 31 35 34 45 38 41 31 31 33 43 33 31 44 44 30 41 44 33 32 46 37 46 33 41 33 36 36 41 38 30 45 38 31 33 36 39 37 39 44 38 46 35 41 31 30 31 44 33 44 32 39 44 36 46 37 32 } //01 00  66840DDA154E8A113C31DD0AD32F7F3A366A80E8136979D8F5A101D3D29D6F72
		$a_80_1 = {53 6c 65 65 70 } //Sleep  01 00 
		$a_80_2 = {4f 4d 4d 61 70 70 } //OMMapp  01 00 
		$a_80_3 = {44 42 62 68 45 51 } //DBbhEQ  01 00 
		$a_80_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //DebuggableAttribute  01 00 
		$a_80_5 = {74 4b 7a 42 45 47 } //tKzBEG  01 00 
		$a_80_6 = {25 78 45 4b 63 58 } //%xEKcX  01 00 
		$a_80_7 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //ClassLibrary  01 00 
		$a_80_8 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  01 00 
		$a_80_9 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //ICryptoTransform  00 00 
	condition:
		any of ($a_*)
 
}