
rule VirTool_Win32_VBInject_BAB_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAB!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 50 93 21 00 [0-20] 05 06 6d 20 00 [0-20] 39 01 [0-20] 75 95 [0-20] 83 e9 04 [0-20] 68 53 14 25 00 [0-20] 58 [0-90] 05 fa eb 2d 00 [0-20] 39 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}