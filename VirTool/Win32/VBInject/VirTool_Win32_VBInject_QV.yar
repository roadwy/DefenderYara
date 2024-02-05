
rule VirTool_Win32_VBInject_QV{
	meta:
		description = "VirTool:Win32/VBInject.QV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {58 59 59 59 90 09 06 00 c7 85 90 01 02 ff ff 90 00 } //01 00 
		$a_03_1 = {66 85 f6 7f 90 01 01 66 81 c6 ff 00 0f 90 01 02 00 00 00 eb ee 90 00 } //01 00 
		$a_03_2 = {59 50 00 00 e8 90 01 03 ff 90 09 06 00 c7 85 90 01 02 ff ff 90 00 } //01 00 
		$a_03_3 = {ff e8 00 00 00 90 09 09 00 6a 01 90 01 02 c7 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}