
rule Trojan_Win32_Stratklonk_A{
	meta:
		description = "Trojan:Win32/Stratklonk.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {6c 00 6f 00 61 00 64 00 65 00 72 00 2d 00 73 00 79 00 73 00 5c 00 4c 00 6f 00 61 00 64 00 73 00 4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 69 00 73 00 5c 00 6b 00 61 00 63 00 } //02 00 
		$a_01_1 = {d2 00 c9 00 c5 00 ab 00 d5 00 d4 00 d5 00 d3 00 c8 00 c5 00 dd 00 d3 00 d4 00 d2 00 c5 00 cd 00 } //02 00 
		$a_01_2 = {cd 00 d8 00 dd 00 da 00 78 01 1c 20 dc 02 e1 00 dc 00 db 00 14 20 cc 00 ce 00 d2 00 cd 00 d9 00 } //01 00 
		$a_01_3 = {8b d0 8d 4d e4 ff d7 8b d0 8d 4b 4c ff d6 8d 45 e4 8d 4d e8 50 51 6a 02 ff 15 } //01 00 
		$a_01_4 = {8b 55 0c 8d 4d b8 0f bf c3 51 50 8b 02 c7 45 c0 01 00 00 00 50 c7 45 b8 02 00 00 00 ff 15 } //00 00 
		$a_00_5 = {80 10 00 } //00 a6 
	condition:
		any of ($a_*)
 
}