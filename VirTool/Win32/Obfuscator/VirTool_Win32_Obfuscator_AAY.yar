
rule VirTool_Win32_Obfuscator_AAY{
	meta:
		description = "VirTool:Win32/Obfuscator.AAY,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {e1 05 be c7 45 ?? ?? e1 05 be ff 15 ?? ?? ?? ?? 6a ?? ff 15 ?? ?? ?? ?? 85 c0 0f 8f 90 09 04 00 c7 45 } //1
		$a_03_1 = {e2 05 be 8b 45 ?? 8b 4d ?? 0f af c1 89 45 ?? 8d 45 ?? 56 89 45 ?? be ?? 68 62 7b e9 90 09 04 00 c7 45 } //1
		$a_03_2 = {c7 45 b8 3b e1 05 be [0-0c] c7 45 f0 00 00 00 00 [0-18] c7 45 b8 3a e1 05 be } //1
		$a_03_3 = {3d db e3 05 be [0-0c] 0f 85 90 16 [0-0c] 81 7d d8 2a e1 05 be [0-0c] 0f 85 90 16 [0-0c] 8b 45 dc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}