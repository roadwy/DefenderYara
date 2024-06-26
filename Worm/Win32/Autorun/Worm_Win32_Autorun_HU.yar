
rule Worm_Win32_Autorun_HU{
	meta:
		description = "Worm:Win32/Autorun.HU,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_01_1 = {25 73 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //02 00  %s\autorun.inf
		$a_01_2 = {25 73 5c 25 64 2d 25 64 2d 25 64 2e 6a 70 67 } //01 00  %s\%d-%d-%d.jpg
		$a_01_3 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 61 75 74 6f 72 75 6e 2e } //01 00  \system32\drivers\autorun.
		$a_01_4 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 25 73 2e 65 78 65 } //01 00  shell\explore\Command=%s.exe
		$a_01_5 = {41 64 6d 69 6e 69 73 74 72 61 64 6f 72 20 64 65 20 74 61 72 65 61 73 20 64 65 20 57 69 6e 64 6f 77 73 } //00 00  Administrador de tareas de Windows
	condition:
		any of ($a_*)
 
}