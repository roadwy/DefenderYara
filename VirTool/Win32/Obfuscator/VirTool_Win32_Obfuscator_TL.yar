
rule VirTool_Win32_Obfuscator_TL{
	meta:
		description = "VirTool:Win32/Obfuscator.TL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 30 04 00 00 68 ?? ?? ?? ?? ff 15 } //1
		$a_03_1 = {8b 45 10 25 ff 00 00 00 85 c0 74 ?? 8b 4d 0c 8b 11 03 55 f8 8b 45 0c 89 10 eb ?? 8b 4d 0c 8b 11 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}