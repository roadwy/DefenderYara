
rule VirTool_Win32_Obfuscator_CG{
	meta:
		description = "VirTool:Win32/Obfuscator.CG,SIGNATURE_TYPE_PEHSTR,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {60 e9 01 00 00 00 } //1
		$a_01_1 = {64 a1 30 00 00 00 8b 40 68 85 c0 74 02 eb } //1
		$a_01_2 = {31 d2 64 ff 32 64 89 22 cd 03 8b 64 24 08 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}