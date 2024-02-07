
rule Trojan_Win32_Allegato_MA_MTB{
	meta:
		description = "Trojan:Win32/Allegato.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {f0 08 6e cf ee 88 da ae 07 13 12 94 ee 94 ad de 71 72 c2 2d 85 c2 9a 53 0f 91 c7 70 6d ad 67 e7 2e bf 10 89 46 79 15 6f 93 39 3f 67 } //05 00 
		$a_01_1 = {df 7a bc 3f 22 d7 52 ec 10 d7 d2 45 6e de 4a 89 74 d5 6b 1e d4 11 db ac 60 ce 63 61 ff 92 16 84 11 2d 92 dd ec a1 13 f8 05 6a 17 } //05 00 
		$a_01_2 = {06 00 34 00 35 00 36 00 39 00 37 00 44 00 06 00 43 00 33 00 43 00 30 00 41 00 45 00 06 } //03 00 
		$a_01_3 = {68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  host.exe
		$a_01_4 = {54 53 68 69 66 74 53 74 61 74 65 } //01 00  TShiftState
		$a_01_5 = {54 4b 65 79 50 72 65 73 73 45 76 65 6e 74 } //01 00  TKeyPressEvent
		$a_01_6 = {4d 6f 75 73 65 50 6f 73 } //01 00  MousePos
		$a_01_7 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00  GetTickCount
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Allegato_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Allegato.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {da d5 d5 9a dd 51 18 dc 4c d9 9d b4 df 1e 83 75 3b a7 ea 24 54 00 ff 68 59 04 0b 0d cc ca ba 24 99 80 9d a8 e7 50 95 87 23 02 c9 c5 b8 ca 38 d2 } //05 00 
		$a_01_1 = {0b 8a d8 7d 71 a9 ee 48 c2 26 36 cf c9 7b 79 19 75 7d 0c b1 d9 2b 16 c8 ee 84 ee 4c 58 ed 67 93 75 cf 96 8b a0 5e f1 d6 af c6 26 47 ae ff 94 bb } //05 00 
		$a_01_2 = {23 f0 1b da 4d 8c 3c 8a d6 ee ec d3 c4 e9 2c 9a 71 6c 71 95 b2 37 a0 71 b7 a7 6a 52 ce 3f 57 d8 0b 77 c8 47 91 d5 9b e5 c3 14 97 46 7c 44 d5 ee 56 b1 b5 07 1d fb b5 8c e4 71 dc ba 60 b6 a2 d0 } //03 00 
		$a_01_3 = {e0 00 8e 81 0b 01 02 19 00 e8 05 00 00 7c 0e 00 00 00 00 00 38 95 05 00 00 10 00 00 00 00 06 00 00 00 40 } //00 00 
	condition:
		any of ($a_*)
 
}