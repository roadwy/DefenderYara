
rule VirTool_Win32_VBInject_PN{
	meta:
		description = "VirTool:Win32/VBInject.PN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {4d b8 8b 49 0c 8b 3d 90 01 02 40 00 90 00 } //02 00 
		$a_00_1 = {59 00 61 00 6c 00 65 00 48 00 69 00 73 00 74 00 6f 00 72 00 69 00 63 00 6f 00 2e 00 76 00 62 00 70 00 } //01 00 
		$a_00_2 = {ff d6 6a 35 ff d7 8b d0 8d 8d b0 fe ff ff ff d6 68 a0 00 00 00 ff d7 8b d0 } //00 00 
	condition:
		any of ($a_*)
 
}