
rule VirTool_Win32_Injector_gen_T{
	meta:
		description = "VirTool:Win32/Injector.gen!T,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {ac 8b c8 03 f8 d3 c7 85 c0 75 f5 } //1
		$a_01_1 = {8b 47 28 01 05 } //2
		$a_01_2 = {32 fb c0 c1 1b fe cf 80 ff 01 75 f6 32 ca 32 ed } //1
		$a_01_3 = {0f 31 2b c6 25 00 f0 ff ff 0c 05 33 c9 0f 00 c1 03 c1 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}