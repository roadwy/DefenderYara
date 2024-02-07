
rule Ransom_Win32_Somhoveran_A{
	meta:
		description = "Ransom:Win32/Somhoveran.A,SIGNATURE_TYPE_PEHSTR_EXT,04 01 ffffffdc 00 08 00 00 64 00 "
		
	strings :
		$a_01_0 = {be 3c 00 00 00 99 f7 fe 89 55 fc 8b c1 b9 10 0e 00 00 99 f7 f9 8b f0 8d 45 f4 50 89 75 dc c6 45 e0 00 8b 45 fc } //32 00 
		$a_01_1 = {cd e5 e2 e5 f0 ed fb e9 20 ea ee e4 21 00 } //32 00 
		$a_01_2 = {cf f0 e5 e2 fb f8 e5 ed 20 eb e8 ec e8 f2 20 ef ee ef fb f2 ee ea 21 } //1e 00 
		$a_01_3 = {32 33 3a 33 30 3a 30 30 00 } //1e 00 
		$a_01_4 = {39 33 38 37 32 33 35 34 36 30 31 31 38 37 34 33 39 } //14 00  93872354601187439
		$a_01_5 = {53 65 72 76 69 63 65 41 6e 74 69 57 69 6e 4c 6f 63 6b 65 72 2e 65 78 65 } //14 00  ServiceAntiWinLocker.exe
		$a_01_6 = {41 6e 74 69 57 69 6e 4c 6f 63 6b 65 72 54 72 61 79 2e 65 78 65 } //14 00  AntiWinLockerTray.exe
		$a_01_7 = {4e 6f 4d 61 6e 61 67 65 4d 79 43 6f 6d 70 75 74 65 72 56 65 72 62 } //00 00  NoManageMyComputerVerb
		$a_00_8 = {87 10 00 00 ea 1b a2 0f ee de c5 f6 73 b3 ba 84 5d 06 05 00 5d 04 00 00 c5 f9 02 80 5c 22 00 00 c6 f9 02 80 00 00 01 00 1e 00 0c 00 d1 41 42 6c 61 63 6f 6c 65 2e 4b 56 00 00 01 40 05 82 59 00 04 00 29 a0 00 00 00 00 00 ff ff ff ff 95 00 00 00 76 61 6c 75 65 3d 22 61 70 } //70 6c 
	condition:
		any of ($a_*)
 
}