
rule VirTool_Win32_CeeInject_AP{
	meta:
		description = "VirTool:Win32/CeeInject.AP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 1c 8d 41 15 32 04 32 32 c1 34 15 88 04 32 83 f9 05 7e 04 33 c9 eb 01 41 42 3b d7 7c e4 } //01 00 
		$a_01_1 = {c7 45 fc af be ba ba 89 55 f8 eb 06 8d 9b 00 00 00 00 8d 4d fc 8b c7 be 03 00 00 00 8d 9b 00 00 00 00 8a 18 3a 19 75 05 40 41 4e 75 f5 } //01 00 
		$a_01_2 = {89 07 8b 7d 08 c7 45 f8 dd cc bb aa 89 55 fc eb 06 8d 9b 00 00 00 00 8d 4d f8 8b c7 be 03 00 00 00 8d 9b 00 00 00 00 8a 18 3a 19 75 } //01 00 
		$a_03_3 = {8d 49 00 8d 50 0b 32 91 90 01 03 00 32 d0 80 f2 0b 88 91 90 01 03 00 83 f8 05 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}