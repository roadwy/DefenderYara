
rule VirTool_Win32_Obfuscator_TY{
	meta:
		description = "VirTool:Win32/Obfuscator.TY,SIGNATURE_TYPE_PEHSTR,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 88 00 02 00 00 81 39 41 63 74 78 74 } //2
		$a_01_1 = {40 64 39 41 21 75 } //1 @d9A!u
		$a_01_2 = {83 c1 18 83 c1 18 64 8b 01 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}