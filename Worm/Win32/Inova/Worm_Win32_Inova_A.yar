
rule Worm_Win32_Inova_A{
	meta:
		description = "Worm:Win32/Inova.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2a 20 20 20 20 5b 2a 5d 4b 65 79 6c 6f 67 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2a 2f } //01 00  /*    [*]Keylog               */
		$a_01_1 = {72 65 67 20 61 64 64 20 48 4b 63 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 } //01 00  reg add HKcU\Software\Microsoft\Windows\CurrentVersion\Run /v
		$a_01_2 = {78 63 6f 70 79 20 25 43 44 25 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 20 2f 59 20 2f 68 20 2f 6b 20 2f 72 20 25 57 49 4e 44 49 52 25 5c 73 79 73 74 72 61 79 } //00 00  xcopy %CD%\autorun.inf /Y /h /k /r %WINDIR%\systray
	condition:
		any of ($a_*)
 
}