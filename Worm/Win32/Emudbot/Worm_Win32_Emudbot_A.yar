
rule Worm_Win32_Emudbot_A{
	meta:
		description = "Worm:Win32/Emudbot.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 4c 6f 67 2e 70 68 70 3f 64 6c 3d 90 02 04 26 6c 6f 67 3d } //1
		$a_01_1 = {25 7e 64 30 5c 61 75 74 6f 72 75 6e 2e 76 62 73 } //1 %~d0\autorun.vbs
		$a_01_2 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 61 75 74 6f 72 75 6e 2e 62 61 74 } //1 shell\Auto\command=autorun.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}