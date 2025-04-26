
rule VirTool_Win32_Obfuscator_RK{
	meta:
		description = "VirTool:Win32/Obfuscator.RK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 8b 36 e9 } //2
		$a_01_1 = {3d 56 4a 84 53 e9 } //1
		$a_01_2 = {3d 8f a8 a8 24 e9 } //1
		$a_01_3 = {68 66 ae 5b 2d e9 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}