
rule Worm_Win32_Autorun_AEA{
	meta:
		description = "Worm:Win32/Autorun.AEA,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 3b 50 72 6f 67 72 61 6d 2a } //1 Windows;Program*
		$a_01_1 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 44 65 66 61 75 6c 74 3d 31 } //1 shell\open\Default=1
		$a_01_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 73 79 73 6b 65 72 6e 65 6c 2e 65 78 65 } //1 shell\open\Command=syskernel.exe
		$a_03_3 = {3a 5c 4e 65 77 20 46 6f 6c 64 65 72 [0-01] 2e 65 78 65 } //1
		$a_01_4 = {3a 5c 41 75 74 6f 72 75 6e 2e 69 6e 66 } //1 :\Autorun.inf
		$a_01_5 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}