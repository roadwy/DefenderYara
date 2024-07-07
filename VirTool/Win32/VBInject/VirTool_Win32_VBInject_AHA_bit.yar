
rule VirTool_Win32_VBInject_AHA_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHA!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 70 ca 10 00 90 02 10 05 e6 35 31 00 90 02 10 39 41 04 75 90 02 10 68 c0 c6 2d 00 90 02 10 58 90 02 10 05 8d 39 25 00 90 02 10 39 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}