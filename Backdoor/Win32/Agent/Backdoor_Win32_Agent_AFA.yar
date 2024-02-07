
rule Backdoor_Win32_Agent_AFA{
	meta:
		description = "Backdoor:Win32/Agent.AFA,SIGNATURE_TYPE_PEHSTR,29 00 29 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 25 73 20 2f 61 } //0a 00  del %s /a
		$a_01_1 = {5c 63 74 66 6d 6f 6e 2e 65 78 65 } //0a 00  \ctfmon.exe
		$a_01_2 = {5c 53 45 52 56 49 43 45 53 2e 45 58 45 } //0a 00  \SERVICES.EXE
		$a_01_3 = {25 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 25 5c 44 6f 63 75 6d 65 6e 74 73 5c 6d 69 63 72 6f 74 6d 2e 62 61 74 } //01 00  %ALLUSERSPROFILE%\Documents\microtm.bat
		$a_01_4 = {63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 20 25 73 20 25 73 } //01 00  cmd.exe /c copy %s %s
		$a_01_5 = {63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 20 5c 2a 2e 2a } //01 00  cmd.exe /c copy \*.*
		$a_01_6 = {72 65 67 65 64 69 74 2e 65 78 65 20 2f 73 20 2f 65 20 20 25 73 } //00 00  regedit.exe /s /e  %s
	condition:
		any of ($a_*)
 
}