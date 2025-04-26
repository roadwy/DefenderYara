
rule VirTool_Win32_VBInject_ALB_bit{
	meta:
		description = "VirTool:Win32/VBInject.ALB!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 04 24 00 10 40 00 [0-30] 5b [0-30] 8b 03 [0-30] bb 00 00 00 00 [0-30] 81 c3 2d a0 24 00 [0-30] 81 c3 20 ba 6b 00 [0-30] 39 d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}