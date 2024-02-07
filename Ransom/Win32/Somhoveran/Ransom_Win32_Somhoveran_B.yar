
rule Ransom_Win32_Somhoveran_B{
	meta:
		description = "Ransom:Win32/Somhoveran.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {be 3c 00 00 00 99 f7 fe 89 55 fc 8b c1 b9 10 0e 00 00 99 f7 f9 8b f0 8d 45 f4 50 89 75 dc c6 45 e0 00 8b 45 fc } //01 00 
		$a_01_1 = {cd e5 e2 e5 f0 ed fb e9 20 ea ee e4 21 00 } //01 00 
		$a_01_2 = {53 65 72 76 69 63 65 41 6e 74 69 57 69 6e 4c 6f 63 6b 65 72 2e 65 78 65 } //01 00  ServiceAntiWinLocker.exe
		$a_01_3 = {41 6e 74 69 57 69 6e 4c 6f 63 6b 65 72 54 72 61 79 2e 65 78 65 } //01 00  AntiWinLockerTray.exe
		$a_01_4 = {57 61 72 6e 69 6e 67 21 20 57 69 6e 64 6f 77 73 20 42 6c 6f 63 6b 65 64 21 } //00 00  Warning! Windows Blocked!
		$a_00_5 = {5d 04 00 } //00 48 
	condition:
		any of ($a_*)
 
}