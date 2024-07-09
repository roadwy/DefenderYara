
rule Trojan_BAT_Tedy_AT_MTB{
	meta:
		description = "Trojan:BAT/Tedy.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 6a 0a 2b 05 06 17 6a 58 0a 06 04 34 0c 02 06 58 02 06 58 47 03 61 52 2b eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Tedy_AT_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 06 91 1f 48 33 1d 03 06 17 58 91 1f 43 33 14 03 06 18 58 91 1f 46 33 0b 03 06 19 58 91 1f 47 33 02 06 2a 06 1a 59 0a 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Tedy_AT_MTB_3{
	meta:
		description = "Trojan:BAT/Tedy.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 03 02 73 ?? 00 00 0a a2 73 ?? 00 00 0a 28 ?? ?? ?? 0a 0d 08 09 6f ?? ?? ?? 0a 00 00 de 0b 08 2c 07 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Tedy_AT_MTB_4{
	meta:
		description = "Trojan:BAT/Tedy.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 14 00 00 0a 25 72 20 01 00 70 04 6f 15 00 00 0a 00 25 72 32 01 00 70 03 6f 15 00 00 0a 00 28 01 00 00 06 26 2a } //2
		$a_01_1 = {73 65 6e 64 57 65 62 48 6f 6f 6b } //1 sendWebHook
		$a_01_2 = {57 00 65 00 62 00 20 00 44 00 72 00 6f 00 70 00 70 00 65 00 72 00 } //1 Web Dropper
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_Tedy_AT_MTB_5{
	meta:
		description = "Trojan:BAT/Tedy.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0b 00 07 0c 16 0d 2b 32 08 09 9a 13 04 00 11 04 25 2d 04 26 14 2b 05 6f 23 00 00 0a 72 a9 a0 00 70 28 36 00 00 0a 0a 06 28 2c 00 00 0a 13 05 11 05 2c 02 2b 0b 00 09 17 58 0d 09 08 8e 69 32 c8 } //2
		$a_01_1 = {6c 00 6c 00 6f 00 6f 00 73 00 73 00 74 00 74 00 } //1 lloosstt
		$a_01_2 = {69 00 6f 00 6d 00 44 00 6f 00 6d 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 iomDome.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}