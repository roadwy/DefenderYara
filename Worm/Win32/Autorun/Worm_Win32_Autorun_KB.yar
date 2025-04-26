
rule Worm_Win32_Autorun_KB{
	meta:
		description = "Worm:Win32/Autorun.KB,SIGNATURE_TYPE_PEHSTR,28 00 23 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 73 79 73 62 6f 6f 74 2e 73 63 72 } //10 shell\open\Command=sysboot.scr
		$a_01_1 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //10 autorun.inf
		$a_01_2 = {52 65 61 6c 73 63 68 61 64 65 } //10 Realschade
		$a_01_3 = {25 73 63 6f 70 79 20 2f 59 20 22 25 73 22 } //5 %scopy /Y "%s"
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //5 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=35
 
}