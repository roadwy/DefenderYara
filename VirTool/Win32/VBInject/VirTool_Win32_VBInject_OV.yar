
rule VirTool_Win32_VBInject_OV{
	meta:
		description = "VirTool:Win32/VBInject.OV,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 05 ec 19 40 00 6f c6 05 57 19 40 00 6f c6 05 89 1a 40 00 6f c6 05 2c 12 40 00 00 ff 25 3c 10 40 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}