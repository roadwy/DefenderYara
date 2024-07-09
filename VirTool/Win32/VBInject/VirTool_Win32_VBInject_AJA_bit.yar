
rule VirTool_Win32_VBInject_AJA_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJA!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 53 00 42 00 [0-20] 40 [0-20] 40 [0-20] 40 [0-20] 39 41 04 [0-20] 68 4d f7 15 00 [0-20] 58 [0-20] 05 00 09 3d 00 [0-20] 39 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}