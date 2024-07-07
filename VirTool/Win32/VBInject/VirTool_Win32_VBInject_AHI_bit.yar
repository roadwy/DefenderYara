
rule VirTool_Win32_VBInject_AHI_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHI!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 53 00 42 00 90 02 30 40 90 02 30 40 90 02 30 40 90 02 30 39 41 04 90 02 30 b8 49 00 53 00 80 90 02 30 40 90 02 30 40 90 02 30 40 90 02 30 40 90 02 30 39 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}