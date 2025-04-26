
rule VirTool_Win32_VBInject_OW_bit{
	meta:
		description = "VirTool:Win32/VBInject.OW!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 0f 85 [0-30] 41 [0-30] 8b 43 2c [0-30] 31 c8 [0-30] 83 f8 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}