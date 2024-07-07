
rule VirTool_Win32_VBInject_gen_HZ{
	meta:
		description = "VirTool:Win32/VBInject.gen!HZ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7d 0f 6a 1c 68 3c 33 40 00 } //1
		$a_01_1 = {75 10 68 bc d5 40 00 68 f8 37 40 00 } //1
		$a_01_2 = {3b c7 db e2 7d 12 68 c4 00 00 00 68 98 39 40 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}