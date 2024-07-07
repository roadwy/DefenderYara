
rule Worm_Win32_Autorun_ZJ{
	meta:
		description = "Worm:Win32/Autorun.ZJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {c1 e0 10 99 f7 7d 90 01 01 50 90 00 } //1
		$a_00_1 = {42 46 35 30 41 43 36 33 2d 31 39 44 41 2d 34 38 37 45 2d 41 44 34 41 2d 30 42 34 35 32 44 38 32 33 42 35 39 } //1 BF50AC63-19DA-487E-AD4A-0B452D823B59
		$a_00_2 = {6f 70 65 6e 3d 00 00 00 52 75 6e 2e 69 6e 66 } //2
		$a_00_3 = {63 79 63 00 63 3a 5c 72 65 } //2
		$a_00_4 = {73 6f 75 2e 63 6f 6d 2f 62 6d 77 } //1 sou.com/bmw
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1) >=4
 
}
rule Worm_Win32_Autorun_ZJ_2{
	meta:
		description = "Worm:Win32/Autorun.ZJ,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 08 00 00 "
		
	strings :
		$a_01_0 = {56 49 52 54 55 41 4c 20 42 4f 58 20 53 55 43 4b } //3 VIRTUAL BOX SUCK
		$a_01_1 = {56 69 72 74 75 61 6c 20 62 6f 78 20 73 75 63 6b 20 6c 6f 6c } //3 Virtual box suck lol
		$a_01_2 = {4c 69 76 65 55 53 42 2e 65 78 65 } //2 LiveUSB.exe
		$a_01_3 = {41 64 6f 62 65 20 52 65 61 64 65 72 20 55 70 64 61 74 65 72 } //2 Adobe Reader Updater
		$a_01_4 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 25 73 } //1 shellexecute=%s
		$a_01_5 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_01_6 = {25 73 61 75 74 6f 72 75 6e 2e 69 6e 66 } //3 %sautorun.inf
		$a_01_7 = {72 00 75 00 6e 00 64 00 6c 00 69 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //3 rundli32.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3) >=14
 
}