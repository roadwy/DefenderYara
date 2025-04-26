
rule PWS_Win32_OnLineGames_FR{
	meta:
		description = "PWS:Win32/OnLineGames.FR,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 04 00 00 "
		
	strings :
		$a_02_0 = {26 7a 68 75 6a 69 3d [0-10] 26 71 75 3d [0-10] 26 73 65 72 3d [0-10] 26 75 73 65 72 3d [0-10] 26 70 61 73 73 3d } //10
		$a_00_1 = {c1 f9 02 78 11 fd f3 a5 89 c1 83 e1 03 83 c6 03 83 c7 03 f3 a4 fc 5f 5e c3 } //10
		$a_00_2 = {67 61 6d 65 2e 65 78 65 } //1 game.exe
		$a_00_3 = {71 75 6e 69 74 68 6f 6f 6b 64 6c 6c } //1 qunithookdll
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=20
 
}