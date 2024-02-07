
rule Backdoor_Win32_Xtrat{
	meta:
		description = "Backdoor:Win32/Xtrat,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0a 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f be 00 83 f0 90 01 01 8b 8d 90 01 04 03 8d 90 01 04 88 01 90 00 } //01 00 
		$a_01_1 = {63 67 6c 2d 62 69 6e 2f 43 72 70 71 32 2e 63 67 69 } //01 00  cgl-bin/Crpq2.cgi
		$a_01_2 = {63 67 6c 2d 62 69 6e 2f 43 6c 6e 70 70 35 2e 63 67 69 } //01 00  cgl-bin/Clnpp5.cgi
		$a_01_3 = {63 67 6c 2d 62 69 6e 2f 52 77 70 71 31 2e 63 67 69 } //01 00  cgl-bin/Rwpq1.cgi
		$a_01_4 = {63 67 6d 2d 62 69 6e 2f 64 69 65 6f 73 6e 38 33 2e 63 67 69 } //01 00  cgm-bin/dieosn83.cgi
		$a_01_5 = {63 67 6c 2d 62 69 6e 2f 44 77 70 71 33 6c 6c 2e 63 67 69 } //01 00  cgl-bin/Dwpq3ll.cgi
		$a_01_6 = {4a 65 73 75 73 4d 61 64 6f 6e 6e 61 } //01 00  JesusMadonna
		$a_01_7 = {73 65 69 6f 77 33 32 2e 65 78 65 } //01 00  seiow32.exe
		$a_01_8 = {61 71 30 32 31 31 } //01 00  aq0211
		$a_01_9 = {64 65 6c 61 79 2e 79 67 74 6f 2e 63 6f 6d 2f 74 72 61 6e 64 6f 63 73 2f 6d 6d 2f } //00 00  delay.ygto.com/trandocs/mm/
		$a_00_10 = {7e 15 00 00 19 } //2c 7b 
	condition:
		any of ($a_*)
 
}