
rule VirTool_Win32_Obfuscator_AJK{
	meta:
		description = "VirTool:Win32/Obfuscator.AJK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 a4 01 00 00 bb ?? ?? ?? ?? 31 1e 81 eb ?? ?? ?? ?? a5 e2 f5 83 c0 06 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}