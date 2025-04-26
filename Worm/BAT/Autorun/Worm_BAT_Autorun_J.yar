
rule Worm_BAT_Autorun_J{
	meta:
		description = "Worm:BAT/Autorun.J,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //2 [autorun]
		$a_01_1 = {79 00 72 00 66 00 65 00 76 00 45 00 38 00 68 00 6d 00 36 00 39 00 54 00 57 00 62 00 4f 00 77 00 61 00 4d 00 6c 00 33 00 2e 00 65 00 78 00 65 00 } //4 yrfevE8hm69TWbOwaMl3.exe
		$a_01_2 = {2d 00 3d 00 2d 00 50 00 75 00 62 00 6c 00 69 00 63 00 20 00 4c 00 6f 00 6e 00 65 00 6c 00 79 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 4c 00 6f 00 67 00 73 00 20 00 56 00 31 00 2e 00 30 00 2d 00 3d 00 2d 00 } //4 -=-Public Lonely Logger Logs V1.0-=-
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4) >=10
 
}