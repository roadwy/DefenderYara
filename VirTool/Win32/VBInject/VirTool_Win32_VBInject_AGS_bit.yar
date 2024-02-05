
rule VirTool_Win32_VBInject_AGS_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f 6e 5c 24 04 90 02 20 0f ef d9 90 02 20 0f 7e db 90 02 20 81 fb 90 01 04 75 90 00 } //01 00 
		$a_03_1 = {8b 5c 24 08 90 02 20 39 18 75 90 02 20 8b 5c 24 0c 90 02 20 39 58 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}