
rule VirTool_Win32_Ceeinject_TK_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.TK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 d2 8d 43 01 b9 1d 00 00 00 33 d2 f7 f1 81 fa ff 00 00 00 76 05 e8 90 01 04 8b c7 03 c3 88 10 90 00 } //01 00 
		$a_03_1 = {03 c3 8a 00 90 02 10 89 db 90 02 10 34 11 8b 15 90 01 04 03 d3 88 02 90 02 10 89 db 89 f6 43 81 fb 56 5b 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}