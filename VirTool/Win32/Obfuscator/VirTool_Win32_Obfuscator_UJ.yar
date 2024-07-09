
rule VirTool_Win32_Obfuscator_UJ{
	meta:
		description = "VirTool:Win32/Obfuscator.UJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c2 7f b8 40 00 00 00 e8 90 09 16 00 8d 0d ?? ?? ?? ?? 89 4d f8 83 6d f8 78 8b 15 ?? ?? ?? ?? 8b 12 83 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}