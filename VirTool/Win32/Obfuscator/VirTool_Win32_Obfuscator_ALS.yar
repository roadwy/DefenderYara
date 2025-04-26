
rule VirTool_Win32_Obfuscator_ALS{
	meta:
		description = "VirTool:Win32/Obfuscator.ALS,SIGNATURE_TYPE_PEHSTR_EXT,14 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 07 35 c6 47 01 5e c6 47 02 74 8b 45 ?? 33 d2 } //1
		$a_03_1 = {8a 1b 3a 5f 02 75 ?? 89 b5 ?? ?? ?? ?? 83 c1 02 83 c1 14 8b d1 8b 85 90 1b 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}