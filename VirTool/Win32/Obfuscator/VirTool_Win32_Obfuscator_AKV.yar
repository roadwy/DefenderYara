
rule VirTool_Win32_Obfuscator_AKV{
	meta:
		description = "VirTool:Win32/Obfuscator.AKV,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 e4 a9 52 09 8b 45 ?? 50 e8 ?? ?? ?? ?? 83 c4 08 89 45 ?? 83 7d ?? 00 74 ?? c7 45 90 09 13 00 64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 40 08 89 45 ?? 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}