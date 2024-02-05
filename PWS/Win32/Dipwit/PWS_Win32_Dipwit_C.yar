
rule PWS_Win32_Dipwit_C{
	meta:
		description = "PWS:Win32/Dipwit.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {81 38 57 65 62 4d 75 90 01 01 90 02 01 81 78 08 20 4b 65 65 75 90 01 01 90 02 01 81 78 12 61 73 73 69 90 00 } //02 00 
		$a_03_1 = {d3 c2 87 d9 45 43 e2 ea 8b dd c1 e3 02 5d 5f 8d 85 90 01 04 8d 4d 90 01 01 6a 00 6a 06 6a 02 90 00 } //01 00 
		$a_01_2 = {8b 40 02 8b 00 ab 66 b8 ff d0 66 ab 66 b8 6a 00 66 ab b0 b8 aa } //01 00 
		$a_01_3 = {b8 d9 9b 8b c2 f7 d0 ab } //01 00 
		$a_03_4 = {d1 9b 93 93 f7 15 90 09 06 00 c7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}