
rule VirTool_Win32_VBInject_AFY_bit{
	meta:
		description = "VirTool:Win32/VBInject.AFY!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 01 8d 45 90 01 01 89 45 90 01 01 c7 45 90 01 01 11 20 00 00 8d 45 90 01 01 50 e8 90 09 18 00 8b 45 90 01 01 03 85 90 01 01 ff ff ff 0f b6 00 2b 45 90 01 01 8b 4d 90 01 01 03 8d 90 01 01 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}