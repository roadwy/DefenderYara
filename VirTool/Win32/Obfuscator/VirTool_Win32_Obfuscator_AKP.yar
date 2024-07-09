
rule VirTool_Win32_Obfuscator_AKP{
	meta:
		description = "VirTool:Win32/Obfuscator.AKP,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 16 8b c7 8b 40 3c 03 c7 8b 40 29 3d ?? ?? 00 00 0f 84 ?? ?? ?? ?? 25 ?? 00 00 00 3d ?? 00 00 00 0f 84 ?? ?? ?? ?? cc } //1
		$a_01_1 = {33 c0 8b c3 05 88 00 00 00 ff 10 85 d2 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}