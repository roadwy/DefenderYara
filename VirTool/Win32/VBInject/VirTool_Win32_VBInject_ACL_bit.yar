
rule VirTool_Win32_VBInject_ACL_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACL!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 58 8b ec 83 4b 4b 4b 39 18 75 90 01 01 bb ef 0c 56 8d 4b 4b 4b 39 58 04 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}