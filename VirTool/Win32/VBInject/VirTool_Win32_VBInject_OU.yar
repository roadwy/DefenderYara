
rule VirTool_Win32_VBInject_OU{
	meta:
		description = "VirTool:Win32/VBInject.OU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e2 00 68 64 12 40 00 e8 c1 fa ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}