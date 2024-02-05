
rule VirTool_Win32_CeeInject_XF_bit{
	meta:
		description = "VirTool:Win32/CeeInject.XF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {a1 b0 57 01 04 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 b0 57 01 04 c1 e8 10 25 ff 7f 00 00 c3 } //01 00 
		$a_01_1 = {ff 15 04 10 00 04 81 fe a9 c3 00 00 7e 27 81 bc 24 e0 01 00 00 e4 86 00 00 74 1a 81 bc 24 e4 01 00 00 20 40 3c 00 74 0d 81 bc 24 04 02 00 00 4f b7 23 00 75 76 } //00 00 
	condition:
		any of ($a_*)
 
}