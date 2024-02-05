
rule Trojan_Win32_Wiszr_C{
	meta:
		description = "Trojan:Win32/Wiszr.C,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {79 6f 5a 45 64 48 58 75 4b 76 63 67 62 71 6f 48 61 6c 65 73 51 4d 74 44 6f 52 66 74 4f 7a 62 6b 4e 69 77 45 4d 48 68 6f 6d 50 } //02 00 
		$a_01_1 = {2e 64 6c 6c 00 72 75 6e 6d 65 } //04 00 
		$a_03_2 = {c1 e8 0b 0f af 45 b4 89 45 ac 8b 4d ec 3b 4d ac 73 30 90 02 08 b8 00 08 00 00 90 00 } //02 00 
		$a_01_3 = {8b 4d 10 03 4d f8 0f b6 11 33 c2 8b 4d 18 03 4d fc 88 01 eb ac } //02 00 
		$a_01_4 = {83 c4 18 8d 55 fc 52 68 74 9a 04 00 8b 45 f8 50 e8 } //02 00 
		$a_01_5 = {73 23 8b 4d c8 c1 e1 08 89 4d c8 8b 55 ec c1 e2 08 8b 45 d0 } //00 00 
		$a_00_6 = {5d 04 00 00 03 18 03 80 5c 21 00 00 } //04 18 
	condition:
		any of ($a_*)
 
}