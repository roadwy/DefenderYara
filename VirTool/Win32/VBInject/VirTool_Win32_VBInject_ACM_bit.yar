
rule VirTool_Win32_VBInject_ACM_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACM!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 54 8b ec 83 43 39 18 75 90 01 01 bb 76 06 ab 46 81 c3 76 06 ab 46 39 58 04 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}