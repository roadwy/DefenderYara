
rule VirTool_Win32_VBInject_AJK_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {a1 00 10 40 00 [0-30] 48 [0-30] 81 38 4d 5a [0-30] 75 [0-30] 05 cc 10 00 00 } //1
		$a_03_1 = {81 fa 41 41 41 41 75 90 0a 80 00 8b 17 [0-30] 31 f2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}