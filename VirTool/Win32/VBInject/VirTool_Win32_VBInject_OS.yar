
rule VirTool_Win32_VBInject_OS{
	meta:
		description = "VirTool:Win32/VBInject.OS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 45 8d 85 90 01 01 fa ff ff 50 e8 90 01 03 ff 6a 78 8d 85 90 01 01 fa ff ff 50 e8 90 01 03 ff 6a 00 6a 04 6a 01 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}