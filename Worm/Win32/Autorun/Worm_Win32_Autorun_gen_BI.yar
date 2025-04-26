
rule Worm_Win32_Autorun_gen_BI{
	meta:
		description = "Worm:Win32/Autorun.gen!BI,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_01_1 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 73 63 61 6e 6e 65 72 2e 65 78 65 } //1 shell\Auto\command=scanner.exe
		$a_01_2 = {72 00 65 00 67 00 65 00 64 00 69 00 74 00 20 00 2d 00 73 00 20 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 31 00 2e 00 72 00 65 00 67 00 } //1 regedit -s C:\windows\system32\1.reg
		$a_01_3 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //1 autorun.inf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}