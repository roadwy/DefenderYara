
rule VirTool_Win32_Obfuscator_QJ{
	meta:
		description = "VirTool:Win32/Obfuscator.QJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {1a df 80 1a 1f 80 63 3b 46 4d db e4 57 3a 2d 17 46 2d cb e4 37 4e } //1
		$a_01_1 = {2e 3f ed 54 54 f2 4d 17 26 df 00 26 1f 48 3a 4d 17 c7 10 54 } //1
		$a_01_2 = {1f b7 38 24 37 c7 40 1a df 00 1a 1f 48 3a 38 19 21 42 40 1a ff 53 ed d7 33 } //1
		$a_01_3 = {e4 63 9c 6d fb fa 80 20 18 18 e4 3b 1e 1f 80 1c 18 18 3e 4d eb 26 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}