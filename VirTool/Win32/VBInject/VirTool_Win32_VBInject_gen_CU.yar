
rule VirTool_Win32_VBInject_gen_CU{
	meta:
		description = "VirTool:Win32/VBInject.gen!CU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {7f 24 66 b9 cc 00 e8 90 01 04 50 53 ff 35 90 01 04 e8 90 01 04 8b c6 03 c3 0f 80 90 01 04 8b d8 eb d2 90 00 } //01 00 
		$a_01_1 = {66 b9 e8 00 e8 } //01 00 
		$a_03_2 = {66 2b c7 0f 80 90 01 02 00 00 0f bf c0 50 8b 45 10 ff 30 90 00 } //01 00 
		$a_03_3 = {75 18 68 92 00 00 00 e8 90 01 04 a3 90 01 04 a1 90 01 04 66 83 08 ff c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}