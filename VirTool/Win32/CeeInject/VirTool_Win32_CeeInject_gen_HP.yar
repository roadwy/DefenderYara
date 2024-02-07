
rule VirTool_Win32_CeeInject_gen_HP{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ff 57 68 00 30 00 00 ff 76 50 ff 76 34 ff 35 90 01 04 e8 90 00 } //01 00 
		$a_03_1 = {0f b7 4e 06 3b c1 72 90 09 0b 00 a1 90 01 04 40 a3 90 00 } //01 00 
		$a_03_2 = {8b 46 28 03 46 34 89 90 03 05 04 84 24 90 01 04 45 90 01 01 8d 90 03 02 01 44 24 45 90 00 } //01 00 
		$a_03_3 = {33 db 53 68 00 30 00 00 ff 76 50 e8 90 01 04 53 ff 76 54 57 ff 76 34 90 00 } //01 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}