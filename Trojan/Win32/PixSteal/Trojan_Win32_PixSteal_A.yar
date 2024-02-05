
rule Trojan_Win32_PixSteal_A{
	meta:
		description = "Trojan:Win32/PixSteal.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0e 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {b8 cc cc cc cc f3 ab 8b f4 ff 15 90 01 04 3b f4 e8 90 01 04 8b f4 6a 00 68 90 01 04 ff 15 90 00 } //05 00 
		$a_03_1 = {83 c4 08 8b f4 68 e8 03 00 00 ff 15 90 01 04 3b f4 e8 90 01 04 8b f4 6a 00 6a 00 6a 00 6a 01 6a 00 ff 15 90 01 04 3b f4 e8 90 00 } //02 00 
		$a_01_2 = {43 6f 6e 73 6f 6c 65 57 69 6e 64 6f 77 43 6c 61 73 73 00 } //02 00 
		$a_01_3 = {43 3a 5c 00 43 3a 5c 2a 2e 2a 00 } //01 00 
		$a_01_4 = {29 20 64 6f 20 40 63 6f 70 79 20 2f 79 20 25 78 20 43 3a 5c 00 } //01 00 
		$a_01_5 = {77 61 73 69 74 6e 65 77 00 } //00 00 
	condition:
		any of ($a_*)
 
}