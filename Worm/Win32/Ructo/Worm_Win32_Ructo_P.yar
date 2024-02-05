
rule Worm_Win32_Ructo_P{
	meta:
		description = "Worm:Win32/Ructo.P,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 0a 00 00 02 00 "
		
	strings :
		$a_03_0 = {66 05 80 00 eb 71 8b 13 8d 4d cc 51 56 52 ff 15 90 01 04 8b d0 8d 4d dc ff d7 50 ff 15 90 01 04 33 c9 66 3d 80 00 90 00 } //01 00 
		$a_01_1 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 2f 00 73 00 20 00 2f 00 75 00 } //01 00 
		$a_01_2 = {73 00 6d 00 74 00 70 00 2e 00 62 00 72 00 61 00 2e 00 74 00 65 00 72 00 72 00 61 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00 
		$a_01_3 = {50 00 52 00 4f 00 43 00 45 00 53 00 53 00 4f 00 52 00 5f 00 41 00 52 00 43 00 48 00 49 00 54 00 45 00 43 00 54 00 55 00 52 00 45 00 } //01 00 
		$a_01_4 = {34 00 2e 00 37 00 2e 00 30 00 2e 00 33 00 30 00 30 00 31 00 } //01 00 
		$a_01_5 = {e1 00 f6 00 e7 00 f2 00 f3 00 f8 00 ae 00 e5 00 f8 00 e5 } //01 00 
		$a_01_6 = {cd 00 e5 00 f3 00 f3 00 e5 00 ee 00 e7 00 e5 00 f2 00 d0 } //01 00 
		$a_01_7 = {ed 00 f0 00 ec 00 e1 00 f9 00 e5 00 f2 00 b2 00 } //01 00 
		$a_01_8 = {ed 00 f3 00 e7 00 f3 00 e3 00 ae 00 e4 00 ec 00 } //01 00 
		$a_01_9 = {fa 00 e9 00 f0 00 bb 00 ae 00 f2 00 e1 00 f2 00 } //00 00 
	condition:
		any of ($a_*)
 
}