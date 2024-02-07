
rule VirTool_Win32_VBInject_OT_bit{
	meta:
		description = "VirTool:Win32/VBInject.OT!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 ff 35 18 00 00 00 90 02 30 8b 90 01 01 30 90 02 30 02 90 01 01 02 90 02 30 ff 90 00 } //02 00 
		$a_03_1 = {83 f9 00 0f 85 90 02 40 0f 6e 90 02 40 8b 90 01 01 2c 90 02 30 0f 6e 90 02 30 0f ef 90 02 30 0f 7e 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}