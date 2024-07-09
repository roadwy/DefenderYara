
rule VirTool_Win32_Obfuscator_AKR{
	meta:
		description = "VirTool:Win32/Obfuscator.AKR,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 31 89 85 ?? ?? ff ff 83 a5 ?? ?? ff ff 00 eb 0d 8b 85 ?? ?? ff ff 40 89 85 ?? ?? ff ff 8b 85 ?? ?? ff ff 35 ?? ?? ?? ?? (0f 84 ?? ?? 00 00 74|)} //1
		$a_03_1 = {0f 31 2b 85 ?? ?? ff ff 89 85 ?? ?? ff ff (b8|c7 85) } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}