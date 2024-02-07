
rule Backdoor_Win32_Prosti_AG{
	meta:
		description = "Backdoor:Win32/Prosti.AG,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //01 00  SOFTWARE\Borland\Delphi
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 63 72 65 65 6e 62 6c 61 7a 65 2e 63 6f 6d 2f 63 75 72 76 65 72 2e 70 68 70 } //01 00  http://www.screenblaze.com/curver.php
		$a_01_2 = {5c 53 63 72 42 6c 61 7a 65 2e 73 63 72 } //01 00  \ScrBlaze.scr
		$a_01_3 = {5c 53 63 72 65 65 6e 42 6c 61 7a 65 2e 65 78 65 20 } //01 00  \ScreenBlaze.exe 
		$a_01_4 = {5c 53 63 72 65 65 6e 42 6c 61 7a 65 55 70 67 72 61 64 65 72 2e 62 61 74 } //01 00  \ScreenBlazeUpgrader.bat
		$a_01_5 = {64 65 6c 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 63 72 65 65 6e 42 6c 61 7a 65 2e 65 78 65 } //00 00  del C:\Windows\ScreenBlaze.exe
	condition:
		any of ($a_*)
 
}