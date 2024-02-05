
rule Trojan_Win32_Startpage_WM{
	meta:
		description = "Trojan:Win32/Startpage.WM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 39 31 90 01 02 2e 69 6e 66 6f 90 00 } //01 00 
		$a_01_1 = {2f 63 20 72 65 67 20 61 64 64 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 22 20 2f 76 20 22 53 74 61 72 74 20 50 61 67 65 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 } //01 00 
		$a_01_2 = {b0 c1 d3 ce e4 af c0 c0 c6 f7 32 2e 6c 6e 6b } //01 00 
		$a_01_3 = {b5 e7 d3 b0 2e 75 72 6c } //01 00 
		$a_01_4 = {d3 ce cf b7 2e 75 72 6c } //01 00 
		$a_01_5 = {bd a1 bf b5 6d 6d cd f8 2e 75 72 6c } //00 00 
	condition:
		any of ($a_*)
 
}