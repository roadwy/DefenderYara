
rule Worm_Win32_Kersex_A{
	meta:
		description = "Worm:Win32/Kersex.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 2a 2e 2a 00 } //02 00 
		$a_01_1 = {43 61 73 74 65 72 20 76 31 2e } //02 00  Caster v1.
		$a_01_2 = {45 61 73 79 20 53 63 72 65 65 6e 53 61 76 65 72 20 53 74 75 64 69 6f 20 76 33 } //02 00  Easy ScreenSaver Studio v3
		$a_01_3 = {70 72 6f 6d 74 20 50 72 6f 66 65 73 73 69 6f 6e 61 6c 20 45 6e 67 6c 69 73 68 2d } //02 00  promt Professional English-
		$a_01_4 = {2e 63 7a 69 70 00 } //01 00  挮楺p
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //02 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_6 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 68 61 72 65 64 5c } //02 00  C:\WINDOWS\shared\
		$a_01_7 = {64 65 66 6c 61 74 65 20 31 2e 32 2e 33 20 43 6f 70 79 72 69 67 68 74 20 31 39 39 35 } //00 00  deflate 1.2.3 Copyright 1995
	condition:
		any of ($a_*)
 
}