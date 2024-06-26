
rule PWS_Win32_Nabrek_A{
	meta:
		description = "PWS:Win32/Nabrek.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 68 69 74 65 55 52 4c 2e 74 78 74 00 } //01 00 
		$a_01_1 = {4d 79 4b 42 00 } //01 00 
		$a_01_2 = {44 47 38 46 56 2d 42 39 54 4b 59 2d 46 52 54 39 4a 2d 36 43 52 43 43 2d 58 50 51 34 47 2d } //01 00  DG8FV-B9TKY-FRT9J-6CRCC-XPQ4G-
		$a_01_3 = {2f 74 6f 6e 67 6a 69 2e 68 74 6d 6c } //01 00  /tongji.html
		$a_01_4 = {2f 73 74 65 70 2f 6d 61 69 6e 2e 70 68 70 } //01 00  /step/main.php
		$a_01_5 = {2f 6d 79 62 61 6e 6b 2e 70 68 70 } //01 00  /mybank.php
		$a_01_6 = {3a 39 30 30 30 2f 69 70 72 2e 68 74 6d 6c } //00 00  :9000/ipr.html
		$a_00_7 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}