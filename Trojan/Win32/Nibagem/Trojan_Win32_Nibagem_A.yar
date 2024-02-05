
rule Trojan_Win32_Nibagem_A{
	meta:
		description = "Trojan:Win32/Nibagem.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 13 8b 55 a8 3b 55 e8 77 0b 8b 45 a8 89 45 ac e9 b8 00 00 00 8b 4d a8 3b 4d e8 0f } //01 00 
		$a_01_1 = {64 70 61 73 74 65 2e 64 7a 66 6c 2e 70 6c } //01 00 
		$a_01_2 = {2f 72 61 77 2f 63 35 33 36 35 34 32 32 63 32 38 37 } //01 00 
		$a_01_3 = {2f 69 6d 61 67 65 73 2f 78 6d 6c 2e 70 68 70 3f 76 3d 44 78 43 76 48 6a 51 7a 61 45 42 56 43 58 26 69 64 3d } //01 00 
		$a_01_4 = {6d 65 67 61 62 69 6e 78 } //00 00 
		$a_00_5 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}