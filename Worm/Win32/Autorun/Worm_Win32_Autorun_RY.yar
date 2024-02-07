
rule Worm_Win32_Autorun_RY{
	meta:
		description = "Worm:Win32/Autorun.RY,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  :\autorun.inf
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {6c 6f 63 61 6c 69 70 3d 31 32 37 2e 30 2e 30 2e 31 26 63 6f 6d 70 6e 61 6d 65 3d } //01 00  localip=127.0.0.1&compname=
		$a_01_3 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //00 00  system32\drivers\etc\svchost.exe
	condition:
		any of ($a_*)
 
}