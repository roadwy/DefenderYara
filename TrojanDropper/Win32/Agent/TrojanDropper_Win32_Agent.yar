
rule TrojanDropper_Win32_Agent{
	meta:
		description = "TrojanDropper:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {e8 35 00 00 00 eb 08 c6 80 90 01 04 00 40 80 b8 90 01 04 00 75 ef 68 90 01 04 ff 35 90 01 04 ff 35 90 01 04 68 90 01 04 e8 90 01 01 00 00 00 6a 00 e8 90 01 01 00 00 00 55 8b ec 50 ff 75 08 ff 75 14 e8 90 01 01 00 00 00 6a 00 6a 00 6a 02 6a 00 6a 00 68 00 00 00 c0 90 00 } //01 00 
		$a_03_1 = {8b 4e 08 8b 56 04 51 8b c8 e8 90 01 01 ff ff ff 50 ff 15 90 01 04 8b 35 90 01 04 57 ff d6 53 ff d6 33 c0 b9 11 00 00 00 8d 7c 24 1c f3 ab 8d 54 24 0c 52 8d 44 24 20 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Agent_2{
	meta:
		description = "TrojanDropper:Win32/Agent,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {a1 10 67 40 00 b9 81 2a 00 00 99 f7 f9 a3 94 92 40 00 a1 10 67 40 00 b9 81 2a 00 00 99 f7 f9 89 15 98 92 40 00 8b 15 bc 92 40 00 03 15 10 67 40 00 03 15 14 67 40 00 f7 da b9 02 00 00 00 a1 08 68 40 00 e8 17 fb ff ff 8b 1d 94 92 40 00 85 db 7e 30 c7 06 01 00 00 00 } //01 00 
		$a_00_1 = {73 6f 66 74 77 61 72 65 5c 62 6f 72 6c 61 6e 64 5c 64 65 6c 70 68 69 5c 72 74 6c } //01 00 
		$a_00_2 = {00 6f 70 65 6e 00 } //01 00 
		$a_00_3 = {77 72 69 74 65 66 69 6c 65 } //01 00 
		$a_00_4 = {73 68 65 6c 6c 65 78 65 63 75 74 65 61 } //01 00 
		$a_00_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 50 72 6f 67 2e 45 58 45 } //00 00 
	condition:
		any of ($a_*)
 
}