
rule Worm_Win32_Gamarue_AT{
	meta:
		description = "Worm:Win32/Gamarue.AT,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 6d 58 6a 73 66 89 45 ?? 58 6a 69 66 89 45 ?? 58 6a 65 [0-03] 66 89 45 ?? 58 6a 78 8b c8 66 89 4d ?? 59 66 89 4d ?? 6a 63 8b c8 66 89 4d ?? 59 6a 2e 66 89 4d ?? 59 66 89 4d ?? 8b c8 [0-06] 6a 78 } //2
		$a_01_1 = {8b 08 81 f9 09 13 ac 01 74 34 81 f9 00 1e 4d 7e 74 27 81 f9 01 1e 4d 7e 74 1a 81 f9 00 00 ce ba 74 0d 81 f9 00 e0 1c ca 75 19 8b 4d 10 } //2
		$a_03_2 = {2b f3 8d 04 0b 2b f1 83 ee 05 83 c1 05 c6 00 e9 89 70 01 81 f9 00 40 00 00 77 ?? ff [0-03] 8b [0-03] 8b 45 ?? 8d 04 c8 8d 48 04 83 39 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}