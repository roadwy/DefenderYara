
rule DDoS_Win32_Doscor_A{
	meta:
		description = "DDoS:Win32/Doscor.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 05 00 "
		
	strings :
		$a_00_0 = {33 45 f8 33 45 fc 69 c0 fd 43 03 00 05 c3 9e 26 00 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 8c a7 40 00 } //01 00 
		$a_80_1 = {41 70 70 6c 65 57 65 62 4b 69 74 } //AppleWebKit  01 00 
		$a_80_2 = {68 74 74 70 73 3a 2f 2f 70 73 62 34 75 6b 72 2e 6f 72 67 2f 25 64 2d 25 63 2f } //https://psb4ukr.org/%d-%c/  01 00 
		$a_80_3 = {68 74 74 70 73 3a 2f 2f 63 6f 72 75 2e 77 73 2f } //https://coru.ws/  00 00 
		$a_00_4 = {5d 04 00 00 2a 39 } //03 80 
	condition:
		any of ($a_*)
 
}