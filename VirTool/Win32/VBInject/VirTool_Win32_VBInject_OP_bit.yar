
rule VirTool_Win32_VBInject_OP_bit{
	meta:
		description = "VirTool:Win32/VBInject.OP!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 75 [0-20] 0f 6e d1 [0-20] 0f fe ca [0-20] 8b 40 2c [0-20] 0f 6e f0 [0-20] 0f ef f1 [0-20] 0f 7e f3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}