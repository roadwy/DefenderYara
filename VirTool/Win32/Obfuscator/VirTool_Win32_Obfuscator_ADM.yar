
rule VirTool_Win32_Obfuscator_ADM{
	meta:
		description = "VirTool:Win32/Obfuscator.ADM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 c3 33 45 08 d1 c0 43 e2 f6 89 44 24 1c 61 } //1
		$a_01_1 = {03 76 3c 8b 46 34 6a 40 68 00 30 00 00 ff 76 50 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}