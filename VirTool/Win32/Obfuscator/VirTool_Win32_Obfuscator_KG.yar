
rule VirTool_Win32_Obfuscator_KG{
	meta:
		description = "VirTool:Win32/Obfuscator.KG,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 40 74 14 8d 05 ?? ?? ?? ?? 8b 00 3b 05 ?? ?? ?? ?? 75 02 eb 02 eb e7 } //1
		$a_03_1 = {33 c0 40 74 11 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 75 02 eb 02 eb ea } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}