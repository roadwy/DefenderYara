
rule TrojanDropper_Win32_Alpasog_A{
	meta:
		description = "TrojanDropper:Win32/Alpasog.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 1c 00 33 d8 83 e3 f8 8d 2c c5 00 00 00 00 33 dd c1 e3 04 8b e8 83 e5 80 33 dd 8b e8 c1 e3 11 c1 ed 08 0b dd 03 c3 83 e9 01 75 d4 } //01 00 
		$a_01_1 = {8b 54 24 10 8a cb 8d 1c d5 00 00 00 00 33 da 81 e3 f8 07 00 00 c1 e3 14 c1 ea 08 0b d3 } //01 00 
		$a_01_2 = {33 d8 c1 e3 04 33 d8 8b e8 83 e3 80 c1 e5 07 33 dd c1 e3 11 c1 e8 08 0b c3 } //01 00 
		$a_01_3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 6e 6f 74 65 2e 69 6e 69 } //01 00  c:\windows\note.ini
		$a_01_4 = {75 64 2e 62 61 74 } //01 00  ud.bat
		$a_01_5 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //00 00  %SystemRoot%\System32\svchost.exe -k netsvcs
		$a_01_6 = {00 67 16 } //00 00 
	condition:
		any of ($a_*)
 
}