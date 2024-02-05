
rule VirTool_Win32_VBInject_AFT{
	meta:
		description = "VirTool:Win32/VBInject.AFT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 73 8d 55 90 01 01 52 ff 15 90 01 04 c7 85 90 01 08 c7 85 90 01 08 6a 6e 8d 85 90 01 02 ff ff 50 ff 15 90 01 04 6a 78 8d 8d 90 01 02 ff ff 51 ff 15 90 01 04 c7 85 90 01 08 c7 85 90 01 08 6a 68 8d 95 90 01 02 ff ff 52 ff 15 90 01 04 6a 6b 90 00 } //01 00 
		$a_00_1 = {46 00 6c 00 61 00 77 00 6c 00 65 00 73 00 73 00 54 00 69 00 63 00 54 00 61 00 63 00 54 00 6f 00 65 00 2e 00 76 00 62 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}