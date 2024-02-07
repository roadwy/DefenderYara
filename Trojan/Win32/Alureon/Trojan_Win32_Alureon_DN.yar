
rule Trojan_Win32_Alureon_DN{
	meta:
		description = "Trojan:Win32/Alureon.DN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {76 0f 8a d0 80 c2 90 01 01 30 14 30 83 c0 01 3b c1 72 f1 90 00 } //01 00 
		$a_03_1 = {76 11 8d 9b 00 00 00 00 80 34 18 90 01 01 83 c0 01 3b c6 72 f5 90 00 } //01 00 
		$a_03_2 = {75 0e 83 c6 04 81 fe 90 01 04 72 e7 90 00 } //01 00 
		$a_03_3 = {6a 40 6a 01 ff d6 50 6a 00 ff d6 8b 4c 24 90 01 01 50 6a 00 6a 00 90 00 } //01 00 
		$a_01_4 = {5b 50 41 4e 45 4c 5f 53 49 47 4e 5f 43 48 45 43 4b 5d } //00 00  [PANEL_SIGN_CHECK]
	condition:
		any of ($a_*)
 
}