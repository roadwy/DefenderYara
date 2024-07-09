
rule VirTool_Win32_Obfuscator_JC{
	meta:
		description = "VirTool:Win32/Obfuscator.JC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 8b d9 e2 fb b9 ?? ?? ?? ?? 5b e2 fd 59 51 b9 ?? ?? ?? ?? 53 8b d9 51 b9 ?? ?? ?? ?? 8b d9 e2 fc 59 5b e2 ef 59 90 09 06 00 51 b9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}