
rule VirTool_Win32_Obfuscator_AKW{
	meta:
		description = "VirTool:Win32/Obfuscator.AKW,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 21 43 34 12 b9 ff ff ff 77 8b 44 24 00 f7 d0 c1 c8 03 2b c1 89 04 24 49 75 ef 58 35 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}