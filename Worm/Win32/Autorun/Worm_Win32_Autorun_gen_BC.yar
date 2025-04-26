
rule Worm_Win32_Autorun_gen_BC{
	meta:
		description = "Worm:Win32/Autorun.gen!BC,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //1 [autorun]
		$a_01_1 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 41 00 75 00 74 00 6f 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 53 00 6f 00 6e 00 67 00 2e 00 65 00 78 00 65 00 } //1 shell\Auto\command=Song.exe
		$a_01_2 = {53 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00 53 00 6f 00 6e 00 67 00 2e 00 65 00 78 00 65 00 } //1 Shellexecute=Song.exe
		$a_01_3 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 65 00 63 00 70 00 6f 00 6c 00 2e 00 65 00 78 00 65 00 } //1 \system32\secpol.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}