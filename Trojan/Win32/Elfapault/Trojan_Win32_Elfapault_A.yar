
rule Trojan_Win32_Elfapault_A{
	meta:
		description = "Trojan:Win32/Elfapault.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {6a 00 8d 4c 24 14 51 6a 40 8d 54 24 38 52 56 ff d7 66 81 7c 24 2c 4d 5a 75 } //02 00 
		$a_01_1 = {8d 55 14 8b 0a 3b ce 73 02 8b f1 83 c2 28 48 75 f2 8b 7c 24 2c 8b 4c 24 18 6a 00 } //02 00 
		$a_01_2 = {33 c9 66 8b 0a 8b c1 25 ff 0f 00 00 03 06 81 e1 00 f0 00 00 03 c7 81 f9 00 30 00 00 75 02 01 28 83 c2 02 4b } //01 00 
		$a_01_3 = {6e 74 64 6c 6c 2e 64 6c 6c 00 00 00 5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 } //01 00 
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}