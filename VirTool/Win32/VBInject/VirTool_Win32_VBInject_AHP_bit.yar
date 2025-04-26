
rule VirTool_Win32_VBInject_AHP_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHP!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 30 00 00 00 [0-20] 64 ff 30 [0-20] 58 eb [0-20] 8b 40 0c [0-20] 8b 40 14 [0-20] 8b 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}