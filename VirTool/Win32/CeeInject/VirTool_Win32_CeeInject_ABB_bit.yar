
rule VirTool_Win32_CeeInject_ABB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 8a 91 90 01 04 80 f2 ba 88 10 41 90 00 } //01 00 
		$a_03_1 = {5f 5e 5b c3 90 0a 70 00 6a 00 68 90 01 04 e8 90 01 04 90 05 10 01 90 83 fb 90 01 01 90 05 10 01 90 7e 90 01 01 90 05 10 01 90 c7 05 90 01 08 90 05 10 01 90 90 02 02 e8 90 01 04 90 05 10 01 90 eb 90 01 01 90 05 10 01 90 4e 75 90 01 01 90 05 10 01 90 5f 5e 5b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}