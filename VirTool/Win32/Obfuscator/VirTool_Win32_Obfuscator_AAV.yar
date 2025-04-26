
rule VirTool_Win32_Obfuscator_AAV{
	meta:
		description = "VirTool:Win32/Obfuscator.AAV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 53 c1 c7 45 } //1
		$a_03_1 = {0f 10 05 04 ?? ?? ?? c7 45 ?? ?? ?? ?? ?? (c7 45|8b 55) } //1
		$a_03_2 = {0f 11 05 04 ?? ?? ?? c7 45 } //1
		$a_03_3 = {33 d2 81 7d ?? ?? ?? ?? ?? 0f 9e c2 } //1
		$a_03_4 = {33 d2 3b c1 0f (95|9f) c2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}