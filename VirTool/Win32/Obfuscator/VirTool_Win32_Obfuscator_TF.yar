
rule VirTool_Win32_Obfuscator_TF{
	meta:
		description = "VirTool:Win32/Obfuscator.TF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 14 83 e0 fd 33 c1 05 bd 04 00 00 a3 ?? ?? ?? 00 c1 c8 10 eb 0c 8b c8 c1 e0 02 d1 c0 83 e0 fa eb e0 c1 c8 08 89 02 83 c2 04 } //1
		$a_01_1 = {c3 8b 44 24 10 83 c0 64 c7 00 c3 00 00 00 b8 00 00 00 00 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}