
rule Ransom_Win32_Somhoveran_A{
	meta:
		description = "Ransom:Win32/Somhoveran.A,SIGNATURE_TYPE_PEHSTR_EXT,04 01 ffffffdc 00 08 00 00 "
		
	strings :
		$a_01_0 = {be 3c 00 00 00 99 f7 fe 89 55 fc 8b c1 b9 10 0e 00 00 99 f7 f9 8b f0 8d 45 f4 50 89 75 dc c6 45 e0 00 8b 45 fc } //100
		$a_01_1 = {cd e5 e2 e5 f0 ed fb e9 20 ea ee e4 21 00 } //50
		$a_01_2 = {cf f0 e5 e2 fb f8 e5 ed 20 eb e8 ec e8 f2 20 ef ee ef fb f2 ee ea 21 } //50
		$a_01_3 = {32 33 3a 33 30 3a 30 30 00 } //30
		$a_01_4 = {39 33 38 37 32 33 35 34 36 30 31 31 38 37 34 33 39 } //30 93872354601187439
		$a_01_5 = {53 65 72 76 69 63 65 41 6e 74 69 57 69 6e 4c 6f 63 6b 65 72 2e 65 78 65 } //20 ServiceAntiWinLocker.exe
		$a_01_6 = {41 6e 74 69 57 69 6e 4c 6f 63 6b 65 72 54 72 61 79 2e 65 78 65 } //20 AntiWinLockerTray.exe
		$a_01_7 = {4e 6f 4d 61 6e 61 67 65 4d 79 43 6f 6d 70 75 74 65 72 56 65 72 62 } //20 NoManageMyComputerVerb
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50+(#a_01_3  & 1)*30+(#a_01_4  & 1)*30+(#a_01_5  & 1)*20+(#a_01_6  & 1)*20+(#a_01_7  & 1)*20) >=220
 
}