
rule VirTool_Win32_Obfuscator_ABF{
	meta:
		description = "VirTool:Win32/Obfuscator.ABF,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 b2 e6 0e 73 15 8b ?? ?? 0f af ?? ?? 89 ?? ?? 8b ?? ?? 83 ?? ?? 89 ?? ?? eb d9 } //1
		$a_03_1 = {83 c4 04 69 c0 ?? 90 04 01 02 6d 6e 00 00 50 68 ?? ?? 40 00 8b ?? 08 d1 [e0 e1 e2] d1 90 04 01 0[0 04 01 0] 3 50 51 5[] } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}