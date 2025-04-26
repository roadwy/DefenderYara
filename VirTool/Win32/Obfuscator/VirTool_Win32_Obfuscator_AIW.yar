
rule VirTool_Win32_Obfuscator_AIW{
	meta:
		description = "VirTool:Win32/Obfuscator.AIW,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d4 d8 40 00 e0 dc e0 dc e0 ab c9 d8 b4 d6 d3 c7 a5 c8 c8 d6 c9 d7 d7 e0 b0 d3 c5 c8 b0 cd c6 d6 c5 d6 dd a5 e0 d2 d8 c8 d0 d0 92 c8 d0 d0 e0 ab } //1
		$a_03_1 = {34 70 40 00 2b ?? 5c 71 40 00 [0-02] 30 70 40 00 03 ?? ?? 88 ?? eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}