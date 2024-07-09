
rule VirTool_Win32_Obfuscator_BG{
	meta:
		description = "VirTool:Win32/Obfuscator.BG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c7 04 24 00 00 00 00 b8 ?? ?? ?? ?? 33 c9 c7 44 24 ?? ?? ?? 40 00 81 3c 24 ?? 27 00 00 75 06 8b 54 24 ?? 28 02 ff 44 24 ?? c1 e8 08 41 83 f9 04 75 0a b8 ?? ?? ?? ?? b9 00 00 00 00 81 7c 24 ?? ?? ?? 40 00 72 d0 ff 04 24 81 3c 24 ?? 27 00 00 76 b5 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}