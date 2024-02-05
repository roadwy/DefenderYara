
rule VirTool_Win32_Ceeinject_NQ_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.NQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 6a 00 52 ff d6 8b 8d 90 01 04 8b 95 90 01 04 89 85 90 00 } //01 00 
		$a_03_1 = {7e 7c 8d 9b 90 01 04 8b 8d 90 01 04 2b 8d 90 01 04 3b f9 72 05 e8 90 01 04 8b 95 90 01 04 8a 04 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}