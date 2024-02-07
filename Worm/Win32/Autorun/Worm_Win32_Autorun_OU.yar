
rule Worm_Win32_Autorun_OU{
	meta:
		description = "Worm:Win32/Autorun.OU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 57 69 6e 64 6f 77 73 2e 65 78 65 } //01 00  %SystemRoot%\System32\Windows.exe
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_01_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 } //01 00  shell\open\Command=regsvr32.exe /s
		$a_01_3 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_03_4 = {43 4c 53 49 44 3d 7b 36 34 35 46 46 30 34 30 2d 35 30 38 31 2d 31 30 31 42 2d 39 46 30 38 2d 30 30 41 41 30 30 32 46 39 35 34 45 7d 90 02 10 3a 5c 52 65 63 79 63 6c 65 64 5c 41 75 74 6f 52 75 6e 2e 64 6c 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}