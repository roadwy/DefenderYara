
rule VirTool_Win32_CeeInject_ABL_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABL!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 90 01 01 8a 00 88 45 90 01 01 8a 45 90 01 01 34 80 8b 55 08 03 55 90 01 01 88 02 ff 45 90 01 01 81 7d f4 90 01 04 75 dc 90 00 } //01 00 
		$a_03_1 = {b9 5c 00 00 00 33 d2 f7 f1 a1 90 01 04 03 05 90 01 04 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}