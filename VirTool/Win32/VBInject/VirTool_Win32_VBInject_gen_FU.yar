
rule VirTool_Win32_VBInject_gen_FU{
	meta:
		description = "VirTool:Win32/VBInject.gen!FU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 a4 4e 0e ec 50 e8 43 00 00 00 83 c4 08 ff 74 24 04 ff d0 ff 74 24 08 50 e8 30 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}