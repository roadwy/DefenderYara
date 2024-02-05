
rule VirTool_Win32_CeeInject_TA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 d2 74 7f 52 ac 30 07 47 5a 4a e2 f3 5b 5e 33 c0 c3 } //01 00 
		$a_03_1 = {b8 c1 00 00 00 89 44 24 04 b9 90 01 04 89 4c 24 08 b8 14 00 00 00 89 44 24 0c 8d 15 90 01 04 89 14 24 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}