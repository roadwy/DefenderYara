
rule VirTool_Win32_VBInject_BAA_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAA!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 ce e3 04 00 [0-20] 05 88 1c 3d 00 [0-20] 39 41 04 [0-20] 68 31 d2 15 00 [0-20] 58 [0-20] 05 1c 2e 3d 00 [0-20] 39 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}