
rule VirTool_Win32_Obfuscator_YQ{
	meta:
		description = "VirTool:Win32/Obfuscator.YQ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 45 08 33 db ff d6 f6 c3 03 8b 4d 08 74 ?? 8a 14 0b 32 15 ?? ?? ?? ?? 80 f2 ?? 88 14 0b f6 c3 01 74 ?? 8a 04 0b 32 05 ?? ?? ?? ?? 34 ?? 88 04 0b 33 d2 8b c3 bf 03 00 00 00 f7 f7 85 d2 74 ?? 8a 14 0b 32 15 ?? ?? ?? ?? 80 f2 ?? 88 14 0b 43 81 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}