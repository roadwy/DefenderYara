
rule TrojanDropper_Win32_Sventore_A{
	meta:
		description = "TrojanDropper:Win32/Sventore.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ce 66 33 04 7d 90 01 04 0f b7 c0 50 e8 90 01 04 47 3b 7c 24 10 7c de 90 00 } //01 00 
		$a_01_1 = {0f be c0 8b d6 8b ce c1 e2 05 c1 e9 02 03 d0 03 ca 33 f1 47 8a 07 84 c0 75 d6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Sventore_A_2{
	meta:
		description = "TrojanDropper:Win32/Sventore.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ce 66 33 04 7d 90 01 04 0f b7 c0 50 e8 90 01 04 47 3b 90 02 03 7c 90 00 } //01 00 
		$a_03_1 = {2b f9 66 8b 8c 56 90 01 04 66 33 0c 55 90 01 04 42 66 89 8c 57 90 01 04 3b 55 0c 7c e2 90 00 } //01 00 
		$a_03_2 = {2b c8 66 8b 84 73 90 01 04 66 33 04 75 90 01 04 66 89 84 71 90 01 04 46 3b f2 7c e3 90 00 } //01 00 
		$a_03_3 = {8b 56 14 0f b7 d8 83 fa 08 72 04 90 09 10 00 66 8b 84 78 90 01 04 66 33 04 7d 90 00 } //01 00 
		$a_01_4 = {0f be c0 8b d6 8b ce c1 e2 05 c1 e9 02 03 d0 03 ca 33 f1 47 8a 07 84 c0 75 d6 } //01 00 
		$a_03_5 = {50 75 15 80 7c 90 01 01 01 4b 75 0e 80 7c 90 01 01 02 05 75 07 80 7c 90 01 01 03 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}