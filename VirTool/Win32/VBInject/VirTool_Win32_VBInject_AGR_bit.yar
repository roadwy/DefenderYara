
rule VirTool_Win32_VBInject_AGR_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGR!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 56 f7 04 00 90 02 10 58 90 02 10 05 00 09 3d 00 90 02 10 39 41 04 75 90 02 10 68 0d be 43 00 90 02 10 58 90 02 10 05 40 42 0f 00 90 02 10 39 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}