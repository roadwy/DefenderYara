
rule VirTool_Win32_Obfuscator_EM{
	meta:
		description = "VirTool:Win32/Obfuscator.EM,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8d 00 29 00 06 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f [0-40] 2f [0-16] 2e (65 78 65|6a 70 67) } //10
		$a_00_1 = {50 52 0f 31 33 d0 01 55 } //10
		$a_02_2 = {c7 04 24 40 00 00 00 e8 ?? ?? 00 00 } //10
		$a_00_3 = {04 24 8b 04 24 } //10
		$a_02_4 = {04 24 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ff ff 8d } //1
		$a_02_5 = {24 fc c7 04 24 ?? ?? ?? ?? e8 ?? ?? 00 00 8d } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*10+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=41
 
}