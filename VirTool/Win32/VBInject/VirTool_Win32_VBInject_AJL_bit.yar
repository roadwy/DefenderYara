
rule VirTool_Win32_VBInject_AJL_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJL!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 00 10 40 00 [0-30] 8b 03 [0-30] bb d4 94 7d 00 [0-30] 81 c3 79 c5 12 00 } //1
		$a_03_1 = {81 fa 41 41 41 41 90 0a 80 00 33 14 24 [0-30] 5e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}