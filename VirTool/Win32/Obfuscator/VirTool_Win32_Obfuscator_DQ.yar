
rule VirTool_Win32_Obfuscator_DQ{
	meta:
		description = "VirTool:Win32/Obfuscator.DQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 58 25 00 00 ff ff 66 8b 00 66 35 ?? ?? 66 3d ?? ?? 74 07 2d 00 00 01 00 eb ?? 25 00 00 ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}