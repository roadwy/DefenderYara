
rule VirTool_Win32_VBInject_ACY_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACY!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {be 00 10 40 00 90 02 20 ad 90 02 20 83 f8 00 90 02 20 74 f5 90 02 20 81 38 55 8b ec 83 75 90 02 20 81 78 04 ec 0c 56 8d 75 90 02 20 ff 75 3c 90 02 20 89 85 c0 00 00 00 90 02 20 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}