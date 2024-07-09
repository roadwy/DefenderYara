
rule VirTool_Win32_Obfuscator_HS{
	meta:
		description = "VirTool:Win32/Obfuscator.HS,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 01 e0 03 c0 3d ?? ?? 00 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}