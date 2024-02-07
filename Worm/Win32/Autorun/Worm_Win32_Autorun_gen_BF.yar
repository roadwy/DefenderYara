
rule Worm_Win32_Autorun_gen_BF{
	meta:
		description = "Worm:Win32/Autorun.gen!BF,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //01 00  [autorun]
		$a_01_1 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 4f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 4b 00 44 00 57 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00  shell\Open\command=KDWin.exe
		$a_01_2 = {5c 00 4b 00 44 00 57 00 49 00 4e 00 5c 00 4b 00 44 00 57 00 69 00 6e 00 2e 00 76 00 62 00 70 00 } //01 00  \KDWIN\KDWin.vbp
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}