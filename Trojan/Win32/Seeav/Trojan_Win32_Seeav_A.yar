
rule Trojan_Win32_Seeav_A{
	meta:
		description = "Trojan:Win32/Seeav.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 4f 01 47 3a cb 75 f8 8b c8 c1 e9 02 f3 a5 68 ff 07 00 00 8b c8 8d 94 24 1d 0c 00 00 } //01 00 
		$a_01_1 = {75 30 8d 85 e0 f7 ff ff 48 8a 48 01 40 3a cb 75 f8 8b } //02 00 
		$a_01_2 = {43 72 65 64 65 6e 74 69 61 6c 73 2e 65 78 65 00 } //01 00 
		$a_01_3 = {25 73 25 64 5f 72 65 73 2e 74 6d 70 00 } //01 00 
		$a_01_4 = {2e 32 34 2e 6a 70 67 00 } //01 00  ㈮⸴灪g
		$a_01_5 = {49 6e 73 74 61 6c 6c 20 53 75 63 63 65 73 73 21 0d 0a 00 } //01 00 
		$a_01_6 = {4d 44 44 45 46 47 45 47 45 54 47 49 5a 00 } //00 00  䑍䕄䝆䝅呅䥇Z
		$a_00_7 = {5d 04 00 00 } //df f8 
	condition:
		any of ($a_*)
 
}