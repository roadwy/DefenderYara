
rule VirTool_Win32_Injector_gen_EQ{
	meta:
		description = "VirTool:Win32/Injector.gen!EQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 3b 56 75 16 80 7b 01 4d 75 10 53 8b c3 c6 03 4d c6 43 01 5a } //1
		$a_01_1 = {6a 6e 58 6a 74 66 89 45 e8 58 6a 64 66 89 45 ea } //1
		$a_01_2 = {8d 43 34 50 8b 87 a4 00 00 00 83 c0 08 50 ff 75 dc ff 56 10 8b 43 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}