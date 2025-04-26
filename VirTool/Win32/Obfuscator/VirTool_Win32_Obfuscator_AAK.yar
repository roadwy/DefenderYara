
rule VirTool_Win32_Obfuscator_AAK{
	meta:
		description = "VirTool:Win32/Obfuscator.AAK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f3 a4 33 c0 90 90 a8 01 8b 0d ?? ?? ?? ?? 74 11 8a 14 01 32 15 ?? ?? ?? ?? 80 f2 ?? 88 14 01 eb 0d 8a 1c 01 8a d0 80 c2 ?? 32 da 88 1c 01 40 3d ?? ?? ?? ?? 7c d0 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}