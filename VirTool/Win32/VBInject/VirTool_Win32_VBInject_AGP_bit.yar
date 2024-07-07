
rule VirTool_Win32_VBInject_AGP_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGP!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 56 f7 04 00 90 02 10 58 90 02 10 05 00 09 3d 00 90 02 10 39 41 04 75 90 02 10 68 4d f7 15 00 90 02 10 58 90 02 10 05 00 09 3d 00 90 02 10 39 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}