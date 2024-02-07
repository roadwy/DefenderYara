
rule PWS_Win32_Cimuz_B{
	meta:
		description = "PWS:Win32/Cimuz.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {be 00 d0 00 00 2d d8 d0 00 00 56 89 45 f0 89 5d f4 89 5d f8 } //01 00 
		$a_01_1 = {8d 34 01 8a c1 f6 ea 30 06 41 3b 4d 08 72 ec ff 75 fc } //01 00 
		$a_01_2 = {74 3a 8b 7e 20 8b 5e 24 03 f9 03 d9 3b c2 89 55 08 76 29 } //01 00 
		$a_01_3 = {8d 59 24 8b 33 8b 3b 8b ce c1 e9 1d c1 ee 1e 83 e1 01 83 e6 01 c1 ef 1f f6 43 03 02 74 13 } //01 00 
		$a_01_4 = {0f b7 0a 8b d9 66 81 e3 00 f0 81 fb 00 30 00 00 } //fb ff 
		$a_00_5 = {2e 76 69 76 69 64 61 73 2e 63 6f 6d } //fb ff  .vividas.com
		$a_00_6 = {4f 43 58 50 4c 41 59 2e 56 50 6c 61 79 65 72 50 72 6f 70 50 61 67 65 2e 31 } //00 00  OCXPLAY.VPlayerPropPage.1
	condition:
		any of ($a_*)
 
}