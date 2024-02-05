
rule Trojan_Win32_Valden_A{
	meta:
		description = "Trojan:Win32/Valden.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 66 69 6c 65 73 00 00 00 73 65 6c 66 64 65 73 74 72 75 63 74 00 00 00 00 2f 43 20 52 44 20 2f 53 20 2f 51 20 25 25 54 45 4d 50 25 25 } //01 00 
		$a_03_1 = {b9 0b 00 00 00 f7 f9 8b fa 83 ff 01 7f 05 bf 90 01 01 00 00 00 33 f6 85 ff 7e 1d e8 90 01 04 33 d2 b9 34 00 00 00 f7 f1 46 3b f7 8a 92 90 01 04 88 54 1e ff 7c e3 90 00 } //01 00 
		$a_01_2 = {70 69 6e 70 61 64 00 00 00 77 69 6e 00 63 63 61 72 64 3d 31 00 63 63 61 72 64 3d 30 } //00 00 
	condition:
		any of ($a_*)
 
}