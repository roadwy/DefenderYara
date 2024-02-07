
rule VirTool_Win32_VBInject_AEX{
	meta:
		description = "VirTool:Win32/VBInject.AEX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {bb 74 23 11 00 c7 46 34 04 00 00 00 8b 46 34 3b c3 89 85 44 fe ff ff 0f 8f 05 01 00 00 dd 05 e8 10 40 00 8b 0e d9 e1 df e0 a8 0d 0f 85 c5 02 00 00 } //01 00 
		$a_03_1 = {8b 48 54 c7 81 90 01 02 00 00 07 a8 5d e3 8b 48 54 c7 81 90 01 02 00 00 6f cf 2e 86 8b 48 54 c7 81 90 01 02 00 00 da 66 0f 73 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}