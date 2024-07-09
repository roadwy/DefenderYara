
rule VirTool_Win32_Obfuscator_AT{
	meta:
		description = "VirTool:Win32/Obfuscator.AT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 58 58 58 58 6b db ?? ff d4 50 8b 40 ?? 05 ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? b8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}