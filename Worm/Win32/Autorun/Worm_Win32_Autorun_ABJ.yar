
rule Worm_Win32_Autorun_ABJ{
	meta:
		description = "Worm:Win32/Autorun.ABJ,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 41 72 63 68 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c 56 42 36 2e 4f 4c 42 } //01 00  C:\Archivos de programa\Microsoft Visual Studio\VB98\VB6.OLB
		$a_01_1 = {5b 61 75 74 6f 72 75 6e 5d } //01 00  [autorun]
		$a_01_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 61 75 74 6f 72 75 6e 2e 65 78 65 } //01 00  shell\open\Command=autorun.exe
		$a_01_3 = {3a 00 20 00 4c 00 33 00 54 00 73 00 20 00 6b 00 69 00 4c 00 4c 00 20 00 42 00 49 00 4c 00 4c 00 20 00 3b 00 29 00 } //00 00  : L3Ts kiLL BILL ;)
	condition:
		any of ($a_*)
 
}