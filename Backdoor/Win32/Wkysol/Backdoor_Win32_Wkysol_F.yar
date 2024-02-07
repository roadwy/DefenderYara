
rule Backdoor_Win32_Wkysol_F{
	meta:
		description = "Backdoor:Win32/Wkysol.F,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 7c 24 1c 53 75 ce 80 7c 24 1d 55 75 c7 8b 44 24 1e 50 e8 } //02 00 
		$a_03_1 = {66 c7 44 24 10 02 00 e8 90 01 04 68 90 01 01 04 00 00 89 44 24 14 e8 90 01 04 66 89 44 24 0e 8d 44 24 0c 6a 10 50 55 33 f6 e8 90 00 } //01 00 
		$a_01_2 = {3f 61 31 3d 25 73 26 61 32 3d 25 73 26 61 33 3d 25 64 26 61 35 3d 25 73 26 61 34 3d 25 73 26 61 36 3d 25 } //01 00  ?a1=%s&a2=%s&a3=%d&a5=%s&a4=%s&a6=%
		$a_01_3 = {4a 41 47 45 58 4c 41 55 4e 43 48 45 52 2e 45 58 45 } //01 00  JAGEXLAUNCHER.EXE
		$a_01_4 = {47 75 61 72 64 43 6f 72 65 2e 64 6c 6c } //01 00  GuardCore.dll
		$a_00_5 = {57 54 46 5c 43 6f 6e 66 69 67 2e 77 74 66 } //00 00  WTF\Config.wtf
	condition:
		any of ($a_*)
 
}