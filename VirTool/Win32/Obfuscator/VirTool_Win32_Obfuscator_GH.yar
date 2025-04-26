
rule VirTool_Win32_Obfuscator_GH{
	meta:
		description = "VirTool:Win32/Obfuscator.GH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 00 00 00 8b ?? 30 8b ?? 54 8b ?? 04 8b ?? 04 8b ?? 04 81 ?? 20 00 20 00 8d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}