
rule TrojanDropper_Win32_Obvod_A{
	meta:
		description = "TrojanDropper:Win32/Obvod.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 05 00 "
		
	strings :
		$a_03_0 = {c3 85 db 74 0d 6a 02 6a 00 6a 00 56 ff 15 90 01 02 40 00 8b 5c 24 1c 8b 54 24 18 8d 4c 24 20 6a 00 90 00 } //05 00 
		$a_01_1 = {32 da 40 3b c6 88 19 7c e6 5b } //06 00 
		$a_03_2 = {ff d7 6a 00 8d 54 24 6c 68 90 01 02 40 00 52 e8 90 01 02 ff ff 8b 44 24 18 6a 00 50 8d 4c 24 7c 56 51 e8 90 00 } //01 00 
		$a_01_3 = {25 73 7b 25 73 7d } //01 00 
		$a_01_4 = {2f 73 20 2f 69 20 25 73 } //01 00 
		$a_01_5 = {6e 75 6c 00 00 20 2f 63 20 64 65 6c 20 00 } //01 00 
		$a_01_6 = {63 6f 6c 6c 65 63 74 2f 62 2e 70 68 70 2f 25 64 2f 25 64 } //00 00 
	condition:
		any of ($a_*)
 
}