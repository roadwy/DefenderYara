
rule VirTool_Win32_Obfuscator_ADG{
	meta:
		description = "VirTool:Win32/Obfuscator.ADG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c2 75 f6 33 c0 b1 ?? 2a ca 28 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 75 ee 8d 05 } //1
		$a_03_1 = {ff 77 50 ff 77 34 ff 75 ?? ff d0 89 45 ?? 8d 85 ?? ?? ?? ?? c7 00 57 72 69 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}