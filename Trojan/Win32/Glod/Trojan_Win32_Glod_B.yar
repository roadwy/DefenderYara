
rule Trojan_Win32_Glod_B{
	meta:
		description = "Trojan:Win32/Glod.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 73 74 61 72 74 73 65 78 00 } //01 00  猀慴瑲敳x
		$a_01_1 = {6f 00 70 00 65 00 6e 00 76 00 } //01 00  openv
		$a_01_2 = {5b 00 41 00 4c 00 54 00 44 00 4f 00 57 00 4e 00 5d 00 } //01 00  [ALTDOWN]
		$a_01_3 = {5b 00 50 00 61 00 73 00 74 00 65 00 5d 00 } //01 00  [Paste]
		$a_01_4 = {53 00 65 00 74 00 74 00 69 00 6d 00 65 00 73 00 73 00 } //01 00  Settimess
		$a_01_5 = {54 00 69 00 6d 00 65 00 73 00 73 00 } //01 00  Timess
		$a_01_6 = {6c 00 6f 00 67 00 73 00 73 00 } //01 00  logss
		$a_01_7 = {5c 00 4d 00 61 00 69 00 6c 00 31 00 2e 00 68 00 74 00 6d 00 } //01 00  \Mail1.htm
		$a_01_8 = {2f 00 70 00 72 00 6f 00 78 00 79 00 63 00 68 00 65 00 63 00 6b 00 65 00 72 00 2f 00 63 00 6f 00 75 00 6e 00 74 00 72 00 79 00 2e 00 68 00 74 00 6d 00 } //01 00  /proxychecker/country.htm
		$a_01_9 = {70 00 75 00 74 00 72 00 61 00 74 00 53 00 5c 00 73 00 6d 00 61 00 72 00 67 00 6f 00 72 00 50 00 5c 00 75 00 6e 00 65 00 4d 00 20 00 74 00 72 00 61 00 74 00 53 00 5c 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 67 00 6e 00 69 00 6d 00 61 00 6f 00 52 00 5c 00 61 00 74 00 61 00 44 00 70 00 70 00 41 00 } //01 00  putratS\smargorP\uneM tratS\swodniW\tfosorciM\gnimaoR\ataDppA
		$a_03_10 = {37 00 31 00 31 00 35 00 36 00 39 00 33 00 90 02 08 26 00 26 00 2a 00 2a 00 45 00 52 00 52 00 4f 00 52 00 2a 00 2a 00 26 00 26 00 90 00 } //00 00 
		$a_00_11 = {7e 15 00 00 ee } //5a b1 
	condition:
		any of ($a_*)
 
}