
rule VirTool_Win32_VBInject_AID_bit{
	meta:
		description = "VirTool:Win32/VBInject.AID!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 59 00 42 00 90 02 30 48 90 02 30 48 90 02 30 48 90 02 30 39 41 04 90 02 30 0f 90 02 30 b8 50 00 53 00 90 02 30 48 90 02 30 48 90 02 30 48 90 02 30 39 01 90 02 30 0f 90 02 30 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}