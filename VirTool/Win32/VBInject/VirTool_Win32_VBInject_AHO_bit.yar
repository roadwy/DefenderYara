
rule VirTool_Win32_VBInject_AHO_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHO!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 b0 d7 13 00 90 02 30 05 a6 28 2e 00 90 02 30 39 01 90 02 30 75 90 02 30 83 e9 04 90 02 30 68 53 14 25 00 90 02 30 58 90 02 30 05 fa eb 2d 00 90 02 30 8b 09 90 02 30 39 c1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}