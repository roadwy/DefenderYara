
rule VirTool_Win32_Obfuscator_AKC{
	meta:
		description = "VirTool:Win32/Obfuscator.AKC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 33 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01 eb c3 } //1
		$a_01_1 = {7c ac 8b 7e 34 3b df 74 74 8b 86 a0 00 00 00 85 c0 74 6a 8b 8e a4 00 00 00 85 c9 74 60 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}