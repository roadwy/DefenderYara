
rule Trojan_BAT_Tedy_ATE_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 6b 00 00 70 28 ?? ?? ?? 06 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0b dd 03 00 00 00 26 de d6 } //1
		$a_01_1 = {16 0a 02 8e 69 17 59 0b 38 16 00 00 00 02 06 91 0c 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32 e6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Tedy_ATE_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 12 04 28 ?? ?? ?? 0a 0d 1e 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 25 17 09 a2 25 18 72 ?? ?? ?? 70 a2 25 19 07 a2 25 1a 72 ?? ?? ?? 70 a2 25 1b 08 a2 25 1c 72 ?? ?? ?? 70 a2 25 1d 06 a2 } //2
		$a_01_1 = {76 74 5f 74 65 73 74 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 76 74 5f 74 65 73 74 2e 70 64 62 } //1 vt_test\obj\Release\vt_test.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Tedy_ATE_MTB_3{
	meta:
		description = "Trojan:BAT/Tedy.ATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {1f 0a fe 02 13 08 11 08 2c 1c 00 72 01 00 00 70 7e 01 00 00 04 28 19 00 00 0a 00 72 1d 00 00 70 80 01 00 00 04 00 00 06 1f 20 fe 01 13 09 11 09 2c 1a } //2
		$a_01_1 = {4b 65 79 4c 6f 67 67 65 72 44 65 6d 6f 5c 4b 65 79 4c 6f 67 67 65 72 44 65 6d 6f 5c 6f 62 6a 5c 44 65 62 75 67 5c 4b 65 79 4c 6f 67 67 65 72 44 65 6d 6f 2e 70 64 62 } //1 KeyLoggerDemo\KeyLoggerDemo\obj\Debug\KeyLoggerDemo.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}