
rule VirTool_Win32_Obfuscator_AJH{
	meta:
		description = "VirTool:Win32/Obfuscator.AJH,SIGNATURE_TYPE_PEHSTR_EXT,64 00 05 00 05 00 00 "
		
	strings :
		$a_09_0 = {68 2e 64 6c 6c 68 65 6c 33 32 68 6b 65 72 6e 54 8b 85 f0 fd ff ff } //1
		$a_09_1 = {68 75 61 6c 41 68 56 69 72 74 54 57 89 e8 8d 80 } //1
		$a_09_2 = {68 64 52 65 61 58 50 68 49 73 42 61 54 57 8b 85 } //1
		$a_0b_3 = {66 83 38 00 74 ?? 8a 08 80 f9 61 7c ?? 80 e9 20 [0-01] c1 c9 08 } //1
		$a_0b_4 = {81 ea 22 67 3f 7a 5a 0f 84 ?? ?? 00 00 52 81 ea 67 22 7a 3f 5a 0f 84 [0-08] 81 fa 28 6d 35 70 } //1
	condition:
		((#a_09_0  & 1)*1+(#a_09_1  & 1)*1+(#a_09_2  & 1)*1+(#a_0b_3  & 1)*1+(#a_0b_4  & 1)*1) >=5
 
}