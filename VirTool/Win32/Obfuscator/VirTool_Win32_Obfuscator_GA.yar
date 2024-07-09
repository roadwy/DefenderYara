
rule VirTool_Win32_Obfuscator_GA{
	meta:
		description = "VirTool:Win32/Obfuscator.GA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 50 51 66 58 59 b0 ?? b3 ?? 00 ?? 66 b8 ?? ?? b7 ?? 66 01 d8 b9 ?? ?? ?? ?? 89 d0 e2 fc } //1
		$a_03_1 = {66 31 c0 30 c0 30 db 30 ff b9 ?? ?? ?? ?? e2 fe 31 c0 31 c9 31 db } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}