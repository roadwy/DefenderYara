
rule Trojan_Win32_Timpin{
	meta:
		description = "Trojan:Win32/Timpin,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //0a 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_02_1 = {74 6d 70 24 24 24 90 02 2e 69 6e 69 90 00 } //01 00 
		$a_00_2 = {00 66 69 6c 65 75 72 6c 00 } //01 00 
		$a_00_3 = {00 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 00 } //01 00  搀睯汮慯晤汩e
		$a_02_4 = {2e 63 6f 2e 6b 72 2f 75 70 90 01 04 2e 70 68 70 00 90 00 } //01 00 
		$a_00_5 = {00 66 69 6c 65 63 6f 75 6e 74 00 } //01 00 
		$a_00_6 = {00 66 69 6c 65 6e 61 6d 65 00 } //00 00  昀汩湥浡e
	condition:
		any of ($a_*)
 
}