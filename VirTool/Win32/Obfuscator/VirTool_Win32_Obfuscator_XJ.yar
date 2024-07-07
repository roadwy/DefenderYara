
rule VirTool_Win32_Obfuscator_XJ{
	meta:
		description = "VirTool:Win32/Obfuscator.XJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5e 56 31 1e ad 01 c3 85 c0 75 f7 } //2
		$a_01_1 = {31 5a 14 83 c2 04 03 5a 10 e2 f5 } //1
		$a_03_2 = {66 b9 86 02 90 09 02 00 90 03 01 01 31 29 c9 90 00 } //1
		$a_03_3 = {66 81 e9 0b fe e8 ff ff ff ff 90 09 02 00 90 03 01 01 31 29 c9 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}