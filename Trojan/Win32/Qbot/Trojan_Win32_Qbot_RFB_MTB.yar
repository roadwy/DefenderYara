
rule Trojan_Win32_Qbot_RFB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 e3 14 00 00 6a 00 e8 90 01 04 8b d8 a1 90 01 04 8b 00 8b 15 90 01 04 81 c2 90 01 04 03 55 90 01 01 33 c2 03 d8 68 e3 14 00 00 6a 00 e8 90 01 04 03 d8 68 e3 14 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RFB_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  1
		$a_80_1 = {46 6f 6e 6b 49 6b 4e } //FonkIkN  1
		$a_80_2 = {4d 71 76 64 45 76 5a 76 } //MqvdEvZv  1
		$a_80_3 = {56 42 46 6a 48 78 46 4f 78 43 } //VBFjHxFOxC  1
		$a_80_4 = {63 6c 45 78 72 56 71 52 } //clExrVqR  1
		$a_80_5 = {6b 72 42 56 45 75 57 6a 64 6c } //krBVEuWjdl  1
		$a_80_6 = {74 67 57 7a 42 54 } //tgWzBT  1
		$a_80_7 = {79 4d 42 65 47 49 } //yMBeGI  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}