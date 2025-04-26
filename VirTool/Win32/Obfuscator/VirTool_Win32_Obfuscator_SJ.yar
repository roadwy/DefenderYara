
rule VirTool_Win32_Obfuscator_SJ{
	meta:
		description = "VirTool:Win32/Obfuscator.SJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 8b 40 28 03 45 08 ff d0 } //1
		$a_01_1 = {81 7d f8 40 1a cd 00 75 04 } //1
		$a_01_2 = {ff 72 10 8b 42 14 03 45 f0 50 8b 42 0c 03 45 08 50 e8 } //1
		$a_01_3 = {64 73 6b 68 02 00 00 80 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}