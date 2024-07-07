
rule VirTool_Win32_VBInject_OP_bit{
	meta:
		description = "VirTool:Win32/VBInject.OP!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 75 90 02 20 0f 6e d1 90 02 20 0f fe ca 90 02 20 8b 40 2c 90 02 20 0f 6e f0 90 02 20 0f ef f1 90 02 20 0f 7e f3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}