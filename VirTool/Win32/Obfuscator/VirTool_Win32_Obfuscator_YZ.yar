
rule VirTool_Win32_Obfuscator_YZ{
	meta:
		description = "VirTool:Win32/Obfuscator.YZ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {60 33 c0 33 db b9 ?? ?? ?? ?? 03 c3 33 45 08 d1 c0 43 e2 f6 89 44 24 1c 61 } //1
		$a_03_1 = {8b 75 08 03 76 3c 6a 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 55 ?? 90 09 03 00 89 45 90 1b 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}