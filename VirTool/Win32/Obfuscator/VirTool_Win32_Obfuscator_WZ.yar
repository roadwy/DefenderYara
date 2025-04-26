
rule VirTool_Win32_Obfuscator_WZ{
	meta:
		description = "VirTool:Win32/Obfuscator.WZ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f0 89 75 ?? 0f af 75 ?? 6a 40 68 00 10 00 00 c1 e6 02 56 57 ff 15 } //1
		$a_03_1 = {6a 40 8d 46 18 89 45 ?? 8b 40 38 68 00 30 00 00 50 6a 00 ff 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}