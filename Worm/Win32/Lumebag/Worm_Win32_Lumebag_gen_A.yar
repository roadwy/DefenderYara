
rule Worm_Win32_Lumebag_gen_A{
	meta:
		description = "Worm:Win32/Lumebag.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0d 00 08 00 00 03 00 "
		
	strings :
		$a_03_0 = {8d 45 f0 50 68 90 90 d0 03 00 e8 90 01 03 ff 05 a0 86 01 00 50 90 00 } //03 00 
		$a_01_1 = {c7 45 e2 50 4b 03 04 66 c7 45 e6 0a 00 ff 75 14 8d 45 ee 50 8d 45 ec 50 e8 } //03 00 
		$a_01_2 = {ff 73 04 8f 07 57 8f 43 04 83 c7 04 c7 07 50 4b 01 02 66 c7 47 04 14 00 66 c7 47 06 0a 00 } //03 00 
		$a_03_3 = {ff 75 10 6a 03 e8 90 01 03 ff 05 d4 07 00 00 66 01 45 f0 ff 75 10 6a 0a 90 00 } //02 00 
		$a_03_4 = {c7 45 d0 00 00 00 00 8b 5d 10 6a 02 6a 00 6a 00 ff 33 e8 90 01 03 00 83 f8 ff 75 90 01 01 e9 90 00 } //02 00 
		$a_03_5 = {f3 a4 8b f8 80 3f d4 75 90 01 01 ff 77 01 8f 45 f0 ff 4d f0 c7 45 f4 56 c3 00 00 ff 75 f4 6a 00 e8 90 01 03 ff 83 6d f4 06 90 00 } //01 00 
		$a_01_6 = {8b 75 0c b8 05 84 08 08 33 d2 f7 26 40 89 06 f7 65 08 } //01 00 
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 75 6c 65 41 70 70 44 61 74 61 } //00 00  Software\MuleAppData
	condition:
		any of ($a_*)
 
}