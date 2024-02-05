
rule Trojan_Win32_Tacmeng_A{
	meta:
		description = "Trojan:Win32/Tacmeng.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0d 00 00 02 00 "
		
	strings :
		$a_01_0 = {3a c2 74 08 8a 46 fe 4e 3a c2 75 f8 8b } //02 00 
		$a_01_1 = {88 5c 24 10 f3 ab 66 ab aa b9 40 00 00 00 33 c0 8d 7c 24 11 6a 54 f3 ab 66 ab aa 8d } //02 00 
		$a_01_2 = {85 d2 74 2d 8b fa 83 c9 ff f2 ae f7 d1 49 74 21 8b fa 83 c9 ff f2 ae f7 d1 2b f9 8b c1 8b f7 8d } //02 00 
		$a_01_3 = {52 50 3f 4d 52 00 7f 01 5a 51 aa 01 89 } //01 00 
		$a_01_4 = {50 72 6f 64 2e 6c 6f 67 00 } //01 00 
		$a_01_5 = {50 72 6f 65 2e 6c 6f 67 00 } //01 00 
		$a_01_6 = {63 74 66 6d 6f 6e 5c 63 74 66 6d 6f 6e 2e 6c 6e 6b 00 } //01 00 
		$a_01_7 = {5f 4f 6e 65 2e 64 6c 6c 00 } //01 00 
		$a_01_8 = {5f 46 72 61 2e 64 6c 6c 00 } //01 00 
		$a_01_9 = {5f 42 79 5f 46 69 66 74 68 5f 00 } //01 00 
		$a_01_10 = {63 63 73 76 63 68 73 74 2e 65 78 65 00 } //01 00 
		$a_01_11 = {43 72 74 52 75 6e 54 69 6d 65 2e 6c 6f 67 00 } //02 00 
		$a_01_12 = {6e 63 74 61 64 62 6c 64 6c 61 2e 65 64 61 6c 63 6c 6e } //00 00 
	condition:
		any of ($a_*)
 
}