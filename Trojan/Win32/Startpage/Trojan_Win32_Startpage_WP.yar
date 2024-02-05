
rule Trojan_Win32_Startpage_WP{
	meta:
		description = "Trojan:Win32/Startpage.WP,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 31 36 39 35 2e 63 6f 6d } //01 00 
		$a_01_1 = {63 6f 70 79 20 22 7b 77 69 6e 7d 5c 73 6e 73 73 31 2e 65 78 65 22 20 22 7b 77 69 6e 7d 5c 73 6e 73 73 2e 65 78 65 22 } //01 00 
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 73 6e 73 73 2e 65 78 65 } //01 00 
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 33 36 30 73 65 2e 65 78 65 } //01 00 
		$a_01_4 = {7b 77 69 6e 7d 5c 66 66 2e 62 61 74 } //01 00 
		$a_01_5 = {63 6f 70 79 20 22 7b 77 69 6e 7d 5c 73 6e 73 73 2e 6c 6e 6b 22 20 22 7b 70 66 6d 7d 5c c6 f4 b6 af 5c 73 6e 73 73 2e 6c 6e 6b 22 } //00 00 
	condition:
		any of ($a_*)
 
}