
rule VirTool_Win32_Obfuscator_AKX{
	meta:
		description = "VirTool:Win32/Obfuscator.AKX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 0f 33 c0 57 51 50 68 80 01 00 00 ff 35 90 01 03 00 ff 15 90 01 03 00 5f 47 47 47 47 4b 75 e0 6a 00 6a 04 68 97 01 00 00 ff 35 90 00 } //1
		$a_01_1 = {c3 4a 23 c2 90 f7 d2 42 03 c2 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}