
rule VirTool_Win32_Obfuscator_UF{
	meta:
		description = "VirTool:Win32/Obfuscator.UF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 8a c8 d3 c0 59 90 13 51 8a c8 d3 c0 59 05 01 01 01 00 05 01 01 01 01 81 f9 ?? ?? ?? ?? 72 03 89 45 ?? e2 ?? 59 8b 5d ?? ac 32 c3 aa } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}