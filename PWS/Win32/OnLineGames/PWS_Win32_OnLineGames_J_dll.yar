
rule PWS_Win32_OnLineGames_J_dll{
	meta:
		description = "PWS:Win32/OnLineGames.J!dll,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 73 3d 25 73 26 75 3d 25 73 26 70 3d 25 73 26 72 3d 25 73 26 6c 3d 25 64 26 6d 3d 25 64 26 73 70 3d 25 73 00 00 6c 69 76 65 75 70 64 61 74 65 2e 65 } //1
		$a_01_1 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_2 = {64 6c 6c 2e 64 61 74 } //1 dll.dat
		$a_01_3 = {71 71 66 66 6f 2e 65 78 65 } //1 qqffo.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}