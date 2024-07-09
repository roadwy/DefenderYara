
rule VirTool_Win32_VBInject_ALA_bit{
	meta:
		description = "VirTool:Win32/VBInject.ALA!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 04 24 00 10 40 00 [0-30] 5b [0-30] 8b 03 [0-30] bb 00 00 00 00 [0-30] 81 c3 40 42 0f 00 [0-30] 81 c3 0d 18 81 00 [0-30] 48 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}