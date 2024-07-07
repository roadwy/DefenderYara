
rule VirTool_Win32_Injector_gen_BH{
	meta:
		description = "VirTool:Win32/Injector.gen!BH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b9 64 00 00 00 88 d8 f3 aa c6 90 01 04 ff 4d c6 90 01 04 ff 70 c6 90 01 04 ff 64 90 00 } //1
		$a_03_1 = {b0 00 ba 0d 00 00 00 89 df 89 d1 f3 aa a0 90 01 04 48 90 00 } //1
		$a_01_2 = {89 d0 c1 e0 02 01 d0 c1 e0 03 8d 04 01 05 f8 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}