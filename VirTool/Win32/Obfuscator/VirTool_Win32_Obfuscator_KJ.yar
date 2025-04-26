
rule VirTool_Win32_Obfuscator_KJ{
	meta:
		description = "VirTool:Win32/Obfuscator.KJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {03 48 3c 89 4d cc 8b 55 cc 0f b7 42 14 8b 4d cc 8d 54 01 18 89 55 dc 6a 40 68 00 30 00 00 } //2
		$a_03_1 = {c6 00 68 8b 0d ?? ?? ?? ?? 89 48 01 c6 40 05 c3 } //2
		$a_03_2 = {6a 40 68 00 30 00 00 8b 45 cc 8b 48 50 51 6a 00 ff 15 ?? ?? ?? ?? 89 45 d4 8b 95 50 ff ff ff 8b 42 3c 8b 4d cc 0f b7 51 06 6b d2 28 8d 84 10 38 01 00 00 } //2
		$a_03_3 = {8d 4c 10 02 8b 15 ?? ?? ?? ?? 03 55 f4 33 0a a1 ?? ?? ?? ?? 03 45 f4 89 08 eb } //1
		$a_01_4 = {8d 54 01 02 8b 45 c4 03 45 f4 33 10 8b 4d c4 03 4d f4 89 11 eb } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}