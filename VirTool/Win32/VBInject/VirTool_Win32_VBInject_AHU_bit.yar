
rule VirTool_Win32_VBInject_AHU_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHU!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 59 00 42 00 90 02 30 48 90 02 30 48 90 02 30 39 41 04 75 90 02 30 b8 50 00 53 00 90 02 30 48 90 02 30 48 90 02 30 48 90 02 30 39 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}