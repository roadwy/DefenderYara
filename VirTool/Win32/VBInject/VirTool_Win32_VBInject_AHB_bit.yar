
rule VirTool_Win32_VBInject_AHB_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHB!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 96 39 14 00 90 02 20 58 90 02 20 05 c0 c6 2d 00 90 02 20 39 41 04 90 02 20 68 cd 7b 34 00 90 02 20 58 90 02 20 05 80 84 1e 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_VBInject_AHB_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AHB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 00 68 00 43 00 44 00 4d 00 51 00 52 00 76 00 4b 00 65 00 00 00 } //01 00 
		$a_01_1 = {00 00 6f 00 66 00 56 00 6a 00 75 00 64 00 63 00 50 00 42 00 64 00 00 00 } //01 00 
		$a_01_2 = {00 00 51 00 75 00 4d 00 5a 00 4d 00 45 00 51 00 54 00 71 00 61 00 6c 00 71 00 6e 00 00 00 } //01 00 
		$a_01_3 = {00 00 71 00 77 00 6b 00 38 00 78 00 69 00 78 00 39 00 4f 00 69 00 47 00 72 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}