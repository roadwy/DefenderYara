
rule Trojan_Win32_Hsow_gen_A{
	meta:
		description = "Trojan:Win32/Hsow.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 63 6f 6d 6d 61 6e 64 00 53 65 44 65 62 75 67 } //01 00  捜浯慭摮匀䑥扥杵
		$a_01_1 = {0b c0 74 2a 89 45 f8 8d 45 dc 50 6a 01 ff 75 f8 e8 } //01 00 
		$a_01_2 = {68 3f 00 0f 00 53 53 e8 } //03 00 
		$a_01_3 = {c7 45 e4 01 00 00 00 8d 75 f4 8d 7d e8 b9 08 00 00 00 f3 a4 c7 45 f0 02 00 00 00 8d 45 e0 } //01 00 
		$a_01_4 = {50 8d 45 e4 50 6a 10 8d 45 e4 50 6a 00 ff 75 fc } //03 00 
		$a_01_5 = {ac aa 85 c0 75 fa 4f 80 7f ff 5c 74 06 66 c7 47 ff 5c 00 66 c7 07 74 00 6a 00 6a 06 } //01 00 
		$a_01_6 = {33 f8 d1 ef b8 0a 00 00 00 33 c0 eb 05 } //03 00 
		$a_01_7 = {64 65 73 6b 74 6f 70 2e 69 6e 69 00 55 8b ec 81 c4 58 f4 ff ff 57 } //00 00 
	condition:
		any of ($a_*)
 
}