
rule Trojan_Win32_Stealer_CAK_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {3a fa 66 2b c1 81 ef 01 00 00 00 80 e4 fd 8a e7 0f b6 07 32 c3 e9 } //01 00 
		$a_00_1 = {c1 c0 02 f8 2d be 59 fc 32 d1 c0 f9 33 d8 3b ca 03 e8 e9 } //01 00 
		$a_01_2 = {55 52 4c 4f 70 65 6e 42 6c 6f 63 6b 69 6e 67 53 74 72 65 61 6d 41 } //01 00 
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 36 34 } //01 00 
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_5 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}