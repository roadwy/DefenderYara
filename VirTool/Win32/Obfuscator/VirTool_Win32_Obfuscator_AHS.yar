
rule VirTool_Win32_Obfuscator_AHS{
	meta:
		description = "VirTool:Win32/Obfuscator.AHS,SIGNATURE_TYPE_PEHSTR_EXT,14 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c6 02 ad c1 c0 10 33 45 ?? ab 83 e9 06 75 f0 } //1
		$a_01_1 = {73 06 83 f8 7f 77 02 41 41 95 89 e8 b3 01 56 89 fe 29 c6 f3 a4 5e eb 8e 00 d2 75 05 8a 16 46 10 d2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}