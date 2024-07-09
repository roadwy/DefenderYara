
rule VirTool_Win32_Obfuscator_HY{
	meta:
		description = "VirTool:Win32/Obfuscator.HY,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 08 00 00 00 ?? ?? cd 2a ?? ?? cd 2a ?? ?? 74 fa ?? ?? ?? ?? cd 2a ?? ?? cd 2a ?? ?? 74 fa } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}