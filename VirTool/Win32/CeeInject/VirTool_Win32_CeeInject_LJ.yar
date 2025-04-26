
rule VirTool_Win32_CeeInject_LJ{
	meta:
		description = "VirTool:Win32/CeeInject.LJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {75 02 eb 12 b8 00 01 00 00 80 fc 01 74 f6 fb 83 c3 02 63 c4 33 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}