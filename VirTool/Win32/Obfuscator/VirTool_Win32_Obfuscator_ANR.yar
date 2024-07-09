
rule VirTool_Win32_Obfuscator_ANR{
	meta:
		description = "VirTool:Win32/Obfuscator.ANR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 78 64 00 02 00 00 75 0f 8b 04 24 c7 04 24 00 00 00 00 ff 74 24 04 50 33 c0 c3 } //1
		$a_03_1 = {74 12 ad 50 2d ?? ?? ?? ?? 0f c8 03 c2 5a ab 83 e9 03 e2 ?? 61 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}