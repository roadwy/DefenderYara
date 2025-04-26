
rule VirTool_Win32_VBInject_AHV_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {39 01 0f 85 [0-30] 59 [0-30] 8b 73 10 [0-30] 89 f7 [0-30] 8b 5e 3c [0-30] 01 de [0-30] 8b 5e 78 } //1
		$a_03_1 = {bb 40 00 00 00 [0-30] 53 [0-30] ba 00 30 00 00 [0-30] 52 [0-30] 68 00 [0-30] 6a 00 [0-30] ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}