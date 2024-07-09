
rule VirTool_Win32_Obfuscator_APC{
	meta:
		description = "VirTool:Win32/Obfuscator.APC,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {dd 45 f8 dc 05 ?? ?? ?? ?? dd 5d f8 dd 45 f8 dc 05 90 1b 00 dd 5d f8 dd 45 f8 dc 25 90 1b 00 dd 5d f8 dd 45 f8 dc 25 90 1b 00 dd 5d f8 [0-40] df e0 f6 c4 41 75 [0-20] 68 04 01 00 00 50 56 ff 15 } //1
		$a_03_1 = {d8 c1 d8 c1 d8 e1 d8 e1 [0-20] df e0 9e 76 [0-30] 68 04 01 00 00 50 [0-20] 68 00 00 00 80 } //1
		$a_03_2 = {7d 11 ff 55 ?? ff 55 90 1b 00 8b 4d fc 83 c1 01 89 4d fc 90 09 80 00 [0-40] c6 45 e0 ?? c6 45 e1 ?? c6 45 e2 ?? c6 45 e3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}