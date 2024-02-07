
rule Worm_Win32_Autorun_AEG{
	meta:
		description = "Worm:Win32/Autorun.AEG,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 44 69 73 61 6c 6c 6f 77 52 75 6e } //01 00  \Policies\Explorer\DisallowRun
		$a_01_1 = {5c 4d 65 6e 75 20 53 74 61 72 74 5c 50 72 6f 67 72 61 6d 79 5c 41 75 74 6f 73 74 61 72 74 5c 53 74 61 72 74 2e 65 78 65 } //01 00  \Menu Start\Programy\Autostart\Start.exe
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 55 53 45 52 4e 41 4d 45 20 65 71 20 } //01 00  taskkill /FI "USERNAME eq 
		$a_01_3 = {2f 69 6d 20 73 76 63 68 6f 73 74 2e 65 78 65 20 2f 66 } //01 00  /im svchost.exe /f
		$a_01_4 = {73 68 65 6c 6c 41 75 74 6f 72 75 6e 63 6f 6d 6d 61 6e 64 3d 73 74 61 72 74 2e 65 78 65 } //01 00  shellAutoruncommand=start.exe
		$a_01_5 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  autorun.inf
		$a_01_6 = {5b 61 75 74 6f 72 75 6e 5d } //00 00  [autorun]
	condition:
		any of ($a_*)
 
}