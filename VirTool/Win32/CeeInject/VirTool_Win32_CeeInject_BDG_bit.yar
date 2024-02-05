
rule VirTool_Win32_CeeInject_BDG_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDG!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 75 fc ff 55 fc 90 09 0d 00 81 c6 90 01 04 73 05 e8 90 01 03 ff 90 00 } //01 00 
		$a_03_1 = {8d 45 fc 50 6a 40 68 90 01 04 56 e8 90 01 03 ff 33 c9 33 db 8b c6 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 71 05 e8 90 01 03 ff 83 c4 08 81 f9 90 01 04 76 05 e8 90 01 03 ff 8a 91 90 01 04 80 90 01 02 88 10 90 02 10 83 c1 01 73 05 e8 90 01 03 ff 83 c1 01 73 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}