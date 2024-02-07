
rule Trojan_WinNT_Mooqkel_A{
	meta:
		description = "Trojan:WinNT/Mooqkel.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 4f 53 54 90 02 05 47 45 54 90 02 05 48 54 54 50 2f 31 2e 31 20 34 30 34 90 00 } //01 00 
		$a_03_1 = {42 41 53 45 90 02 10 61 63 74 69 6f 6e 90 02 05 69 74 65 6d 90 00 } //01 00 
		$a_01_2 = {48 54 54 50 2f 31 2e 31 20 33 30 32 20 46 6f 75 6e 64 } //01 00  HTTP/1.1 302 Found
		$a_01_3 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4d 00 32 00 54 00 64 00 69 00 } //01 00  \Device\M2Tdi
		$a_01_4 = {b9 4e e6 40 bb } //01 00 
		$a_01_5 = {0a 46 42 8a 0e 84 c9 75 ee 3b } //00 00 
		$a_00_6 = {5d 04 00 } //00 b4 
	condition:
		any of ($a_*)
 
}