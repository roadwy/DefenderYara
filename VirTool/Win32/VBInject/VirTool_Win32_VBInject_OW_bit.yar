
rule VirTool_Win32_VBInject_OW_bit{
	meta:
		description = "VirTool:Win32/VBInject.OW!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 0f 85 90 02 30 41 90 02 30 8b 43 2c 90 02 30 31 c8 90 02 30 83 f8 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}