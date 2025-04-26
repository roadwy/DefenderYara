
rule VirTool_Win32_VBInject_AGT_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGT!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 d6 7b 23 00 [0-10] 58 [0-10] 05 80 84 1e 00 [0-10] 39 41 04 [0-10] 68 0d be 43 00 [0-10] 58 [0-10] 05 40 42 0f 00 [0-10] 39 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}