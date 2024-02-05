
rule Trojan_Win32_Startpage_WQ{
	meta:
		description = "Trojan:Win32/Startpage.WQ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6f 75 77 75 6b 65 2e 63 6e 2f 3f } //01 00 
		$a_01_1 = {68 61 6f 64 61 31 32 33 2e 63 6f 6d 2e 63 6e } //01 00 
		$a_01_2 = {5c cd f8 c9 cf b9 ba ce ef 2e 75 72 6c } //01 00 
		$a_03_3 = {71 69 77 6e 6e 61 79 2e 62 61 74 90 01 09 3a 74 72 79 90 01 0c 64 65 6c 20 22 00 90 00 } //01 00 
		$a_03_4 = {53 49 44 5c 7b 38 37 31 43 35 33 38 30 2d 34 32 90 01 60 41 30 2d 31 30 36 39 2d 41 32 45 41 2d 30 38 30 30 32 42 33 30 33 30 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}