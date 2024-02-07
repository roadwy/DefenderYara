
rule Worm_Win32_Autorun_JK{
	meta:
		description = "Worm:Win32/Autorun.JK,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 63 68 6f 20 5b 61 75 74 6f 72 75 6e 5d 20 3e 20 25 77 69 6e 64 69 72 25 5c 41 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  echo [autorun] > %windir%\Autorun.inf
		$a_01_1 = {65 63 68 6f 20 6f 70 65 6e 3d 57 69 6e 6c 6f 61 64 65 72 2e 62 61 74 20 3e 3e 20 25 77 69 6e 64 69 72 25 5c 41 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  echo open=Winloader.bat >> %windir%\Autorun.inf
		$a_01_2 = {73 68 75 74 64 6f 77 6e 20 2f 73 20 2f 66 20 2f 74 20 31 30 20 2f 63 20 22 2e 3a 3a 3a 5b 53 4f 52 52 59 5d 3a 3a 3a 2e 22 } //00 00  shutdown /s /f /t 10 /c ".:::[SORRY]:::."
	condition:
		any of ($a_*)
 
}