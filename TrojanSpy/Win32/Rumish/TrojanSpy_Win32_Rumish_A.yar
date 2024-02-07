
rule TrojanSpy_Win32_Rumish_A{
	meta:
		description = "TrojanSpy:Win32/Rumish.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 22 20 79 61 2e 72 75 } //01 00  er\iexplore.exe" ya.ru
		$a_03_1 = {72 75 6e 65 78 70 6c 90 03 01 00 5f 5c 52 65 6c 65 61 73 65 5c 73 6d 70 68 6f 73 74 2e 70 64 62 90 00 } //01 00 
		$a_00_2 = {25 00 77 00 69 00 6e 00 64 00 69 00 72 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 6d 00 70 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  %windir%\system32\smphost.exe
		$a_01_3 = {2b c6 05 c8 00 00 00 3d e8 03 00 00 7d 0b 68 c8 00 00 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}