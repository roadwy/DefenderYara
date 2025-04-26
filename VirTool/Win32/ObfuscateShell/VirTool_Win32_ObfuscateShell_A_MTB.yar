
rule VirTool_Win32_ObfuscateShell_A_MTB{
	meta:
		description = "VirTool:Win32/ObfuscateShell.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 45 e0 8b 45 ?? c1 e0 02 89 45 ?? 8b 45 ?? c1 f8 04 09 45 ?? 8b 45 ?? 8d ?? ?? 89 55 ?? 8b 55 ?? 88 10 } //1
		$a_01_1 = {89 45 d4 8b 45 d8 c1 e0 06 25 ff 00 00 00 } //1
		$a_03_2 = {89 44 24 04 8d ?? ?? ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 89 04 24 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}