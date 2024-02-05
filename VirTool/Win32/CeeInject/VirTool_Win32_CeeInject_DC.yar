
rule VirTool_Win32_CeeInject_DC{
	meta:
		description = "VirTool:Win32/CeeInject.DC,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {76 6d 77 61 72 65 } //01 00 
		$a_00_1 = {4f 4c 4c 59 44 42 47 } //01 00 
		$a_00_2 = {69 63 75 5f 64 62 67 } //01 00 
		$a_03_3 = {03 01 8b ce 99 f7 f9 8a 84 95 90 01 02 ff ff 30 03 ff 45 10 8b 45 10 3b 45 0c 7c 9e 90 00 } //01 00 
		$a_03_4 = {07 00 01 00 90 09 06 00 c7 85 90 00 } //01 00 
		$a_01_5 = {50 52 4f 43 4d 4f 4e 5f 57 49 4e 44 4f 57 5f 43 4c 41 53 53 } //00 00 
	condition:
		any of ($a_*)
 
}