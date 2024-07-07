
rule VirTool_Win32_Injector_gen_AF{
	meta:
		description = "VirTool:Win32/Injector.gen!AF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 d1 03 c2 25 ff 00 00 80 79 90 01 01 48 0d 00 ff ff ff 40 90 00 } //2
		$a_01_1 = {35 9b 00 00 00 58 } //1
		$a_01_2 = {50 83 f0 0d 58 } //1
		$a_01_3 = {35 14 13 00 00 35 14 13 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}