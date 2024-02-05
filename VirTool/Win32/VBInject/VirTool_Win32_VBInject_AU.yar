
rule VirTool_Win32_VBInject_AU{
	meta:
		description = "VirTool:Win32/VBInject.AU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 35 08 00 0f bf c0 50 8d 4d } //01 00 
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00 
		$a_01_2 = {45 6e 63 72 79 70 74 42 79 74 65 } //01 00 
		$a_01_3 = {21 00 21 00 21 00 21 00 21 00 3d 00 29 00 } //01 00 
		$a_01_4 = {53 00 6b 00 69 00 70 00 6a 00 61 00 63 00 6b 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 46 00 69 00 6c 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}