
rule VirTool_Win32_VBInject_AJS_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJS!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {bb 00 10 40 00 [0-30] 8b 03 [0-30] bb 4d 5a } //1
		$a_03_1 = {bb 00 10 40 00 [0-30] 8b 03 [0-30] bb c0 6e 8f 00 [0-30] 81 c3 8d eb 00 00 } //1
		$a_03_2 = {81 fa 41 41 41 41 75 90 0a 30 00 31 f2 } //1
		$a_03_3 = {83 f9 00 0f 90 0a 30 00 8f 04 08 90 0a 30 00 31 34 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}