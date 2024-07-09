
rule VirTool_Win32_Obfuscator_UA{
	meta:
		description = "VirTool:Win32/Obfuscator.UA,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 8b cc 8b 44 24 04 68 ?? 7b 07 00 ?? 68 00 00 02 00 51 ff 15 ?? ?? ?? ?? 8b c8 ba ?? ?? ?? ?? c1 e9 1c 03 14 24 c1 e0 04 03 c2 8d 4c 0c ?? 89 01 51 68 00 00 02 00 51 ff 15 ?? ?? ?? ?? 83 c4 ?? c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}