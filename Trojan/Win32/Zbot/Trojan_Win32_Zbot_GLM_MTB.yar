
rule Trojan_Win32_Zbot_GLM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 33 45 f0 33 f0 3b f7 75 07 be 4f e6 40 bb eb 0b 85 f3 75 07 8b c6 c1 e0 10 0b f0 89 35 c8 de 40 00 f7 d6 89 35 cc de 40 00 5e 5f 5b c9 c3 } //10
		$a_80_1 = {4c 44 75 68 79 77 73 6f 2e 65 78 65 } //LDuhywso.exe  1
		$a_80_2 = {6f 72 6d 77 6e 72 5a 4b 2e 65 78 65 } //ormwnrZK.exe  1
		$a_80_3 = {66 42 6f 51 71 73 79 7a 2e 65 78 65 } //fBoQqsyz.exe  1
		$a_80_4 = {63 6f 6e 77 75 72 2e 65 78 65 } //conwur.exe  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=14
 
}