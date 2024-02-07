
rule Trojan_Win32_FakeIA_O{
	meta:
		description = "Trojan:Win32/FakeIA.O,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 70 64 65 66 65 6e 64 65 72 32 30 30 39 2e 63 6f 6d 2f 62 75 79 2e 70 68 70 } //0a 00  http://www.pdefender2009.com/buy.php
		$a_00_1 = {ff ff ff ff 24 00 00 00 97 8b 8b 8f c5 d0 d0 88 88 88 d1 8f 9b 9a 99 9a 91 9b 9a 8d cd cf cf c6 d1 9c 90 92 d0 9d 8a 86 d1 8f 97 8f 00 00 00 00 } //01 00 
		$a_00_2 = {ff ff ff ff 13 00 00 00 ac b7 aa ab bb b0 a8 b1 df d2 8d df d2 99 df d2 8b df cf 00 } //01 00 
		$a_02_3 = {41 50 50 44 41 54 41 5c 90 02 0a 2e 67 69 66 90 00 } //01 00 
		$a_02_4 = {c6 02 4c 8b 10 c6 42 01 53 8b 10 90 02 30 50 6a 00 6a 00 e8 90 01 02 ff ff 8b d8 e8 90 01 02 ff ff 85 c0 75 16 54 6a 00 6a 00 68 90 01 04 6a 00 6a 00 e8 62 89 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}