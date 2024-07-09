
rule VirTool_Win32_Obfuscator_ARJ{
	meta:
		description = "VirTool:Win32/Obfuscator.ARJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 42 28 89 45 ?? 6a 00 6a 01 8b 4d ?? 51 ff 55 ?? 68 00 80 00 00 } //2
		$a_03_1 = {85 c0 75 05 e9 ?? ?? ?? ?? 8d 45 ?? 50 68 01 00 80 00 8b 4d ?? 51 68 0e 66 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}