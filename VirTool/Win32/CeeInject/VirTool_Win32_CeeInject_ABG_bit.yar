
rule VirTool_Win32_CeeInject_ABG_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 02 a1 90 01 04 32 0c 02 66 0f be c1 66 89 04 57 42 3b 15 90 01 04 7c df 90 09 05 00 a1 90 00 } //01 00 
		$a_01_1 = {8b 47 08 8b 0f 8a 04 30 32 04 31 88 04 1e } //01 00 
		$a_03_2 = {ff 74 24 04 68 90 01 04 e8 90 01 04 59 50 68 90 01 04 e8 90 01 04 59 50 ff 15 90 01 04 50 ff 15 90 01 04 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}