
rule Worm_Win32_Autorun_LF{
	meta:
		description = "Worm:Win32/Autorun.LF,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {2a 00 5c 00 41 00 64 00 3a 00 5c 00 42 00 65 00 6c 00 61 00 6a 00 61 00 72 00 5c 00 4d 00 72 00 58 00 31 00 5c 00 4d 00 72 00 58 00 2e 00 76 00 62 00 70 00 } //10 *\Ad:\Belajar\MrX1\MrX.vbp
		$a_01_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //1 \Device\PhysicalMemory
		$a_01_2 = {52 00 65 00 67 00 57 00 72 00 69 00 74 00 65 00 } //1 RegWrite
		$a_01_3 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 41 00 75 00 74 00 6f 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 } //1 shell\Auto\command=
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}