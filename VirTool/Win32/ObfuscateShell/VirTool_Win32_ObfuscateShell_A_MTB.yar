
rule VirTool_Win32_ObfuscateShell_A_MTB{
	meta:
		description = "VirTool:Win32/ObfuscateShell.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 e0 8b 45 90 01 01 c1 e0 02 89 45 90 01 01 8b 45 90 01 01 c1 f8 04 09 45 90 01 01 8b 45 90 01 01 8d 90 01 02 89 55 90 01 01 8b 55 90 01 01 88 10 90 00 } //01 00 
		$a_01_1 = {89 45 d4 8b 45 d8 c1 e0 06 25 ff 00 00 00 } //01 00 
		$a_03_2 = {89 44 24 04 8d 90 01 06 89 04 24 e8 90 01 04 8d 90 01 06 89 04 24 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}