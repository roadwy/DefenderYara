
rule VirTool_Win32_Obfuscator_AJO{
	meta:
		description = "VirTool:Win32/Obfuscator.AJO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 8b 02 81 38 04 00 00 80 0f 85 dd 01 00 00 8b 0d ?? ?? ?? 00 83 c1 01 89 0d ?? ?? ?? 00 83 3d ?? ?? ?? 00 26 0f 83 d2 00 00 00 } //1
		$a_01_1 = {b1 3f 3e 30 0c 06 40 92 92 87 e4 3b c7 8b ff 72 ef } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}