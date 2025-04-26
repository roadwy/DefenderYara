
rule VirTool_Win32_VBInject_AHM_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHM!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 b0 d7 13 00 [0-20] 05 a6 28 2e 00 [0-20] 39 01 75 [0-20] 83 e9 04 [0-20] 68 31 d2 15 00 [0-20] 58 [0-20] 05 1c 2e 3d 00 [0-20] 39 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}