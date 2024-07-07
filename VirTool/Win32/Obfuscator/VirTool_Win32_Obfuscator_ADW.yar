
rule VirTool_Win32_Obfuscator_ADW{
	meta:
		description = "VirTool:Win32/Obfuscator.ADW,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {a1 d8 20 00 10 89 45 ec c6 45 fe 8b c6 45 ff 6a c6 45 eb 55 c6 45 f3 ff c7 45 a0 00 00 00 00 c7 85 64 ff ff ff 30 00 00 00 c7 85 68 ff ff ff 03 00 00 00 c7 85 6c ff ff ff 00 00 00 00 c7 85 70 ff ff ff 00 00 00 00 c7 85 74 ff ff ff 00 00 00 00 c7 85 78 ff ff ff 00 00 00 00 } //1
		$a_03_1 = {68 02 00 00 80 ff 15 90 01 04 90 02 ff 68 90 01 01 63 00 10 68 02 00 00 08 30 ff 15 90 1b 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}