
rule TrojanSpy_Win32_Shevonelo_STA{
	meta:
		description = "TrojanSpy:Win32/Shevonelo.STA,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2a 0f 46 88 0a 42 8a 0e 84 c9 75 f4 } //01 00 
		$a_01_1 = {81 ec 80 00 00 00 f3 a5 6a 20 59 8b fc 8d 75 08 f3 a5 } //01 00 
		$a_03_2 = {33 c9 c7 40 40 90 01 04 89 48 64 89 48 60 89 48 68 c7 40 44 90 01 04 c7 40 48 90 01 04 c7 40 4c 90 01 04 c7 40 50 90 01 04 c7 40 54 90 00 } //01 00 
		$a_01_3 = {68 a3 da b7 88 e8 } //01 00 
		$a_01_4 = {68 53 c1 1f 2e e8 } //01 00 
		$a_01_5 = {68 9a 34 63 bc e8 } //01 00 
		$a_01_6 = {68 9d ec 5a 86 e8 } //00 00 
		$a_00_7 = {5d 04 00 } //00 eb 
	condition:
		any of ($a_*)
 
}