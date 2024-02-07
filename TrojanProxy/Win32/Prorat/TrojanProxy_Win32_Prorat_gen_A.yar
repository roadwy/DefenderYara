
rule TrojanProxy_Win32_Prorat_gen_A{
	meta:
		description = "TrojanProxy:Win32/Prorat.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 74 6d 5f 64 55 52 4c 3d 68 74 74 70 3a 2f 2f } //01 00  atm_dURL=http://
		$a_00_1 = {30 30 2d 64 37 62 66 2d 31 31 64 31 2d 39 39 34 37 2d 30 30 63 30 43 66 39 38 62 62 63 39 7d } //01 00  00-d7bf-11d1-9947-00c0Cf98bbc9}
		$a_00_2 = {5c 66 66 73 65 72 76 69 63 65 2e 65 } //01 00  \ffservice.e
		$a_00_3 = {5c 64 5f 73 65 72 76 69 63 65 2e 65 } //02 00  \d_service.e
		$a_00_4 = {80 3c 28 20 74 1b 43 56 4d ff d7 3b d8 7c ee 56 c6 46 08 5c e8 } //03 00 
		$a_02_5 = {74 34 6a 00 8d 84 24 90 05 00 00 6a 00 8d 8c 24 2c 04 00 00 50 51 6a 00 e8 90 01 02 00 00 85 c0 75 15 6a 05 50 8d 94 24 94 05 00 00 50 52 50 50 ff 90 00 } //02 00 
		$a_00_6 = {83 c4 24 a1 8c 10 40 00 8b 30 89 75 8c 80 3e 22 75 3a 46 89 75 8c 8a 06 3a c3 74 04 3c 22 75 f2 80 3e 22 75 04 46 89 75 8c 8a 06 3a c3 74 04 3c 20 76 f2 89 5d d0 8d 45 a4 } //00 00 
	condition:
		any of ($a_*)
 
}