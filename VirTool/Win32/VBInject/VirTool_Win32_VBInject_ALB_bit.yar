
rule VirTool_Win32_VBInject_ALB_bit{
	meta:
		description = "VirTool:Win32/VBInject.ALB!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 04 24 00 10 40 00 90 02 30 5b 90 02 30 8b 03 90 02 30 bb 00 00 00 00 90 02 30 81 c3 2d a0 24 00 90 02 30 81 c3 20 ba 6b 00 90 02 30 39 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}