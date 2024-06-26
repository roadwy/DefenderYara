
rule PWS_Win32_OnLineGames_EU{
	meta:
		description = "PWS:Win32/OnLineGames.EU,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {c6 07 e9 47 2b c7 83 e8 04 89 07 } //05 00 
		$a_03_1 = {66 3d 15 00 74 2d 66 8b 06 50 e8 90 01 04 66 3d 50 00 74 1e 66 8b 06 50 e8 90 01 04 66 3d 99 05 74 0f 66 8b 06 50 e8 90 01 04 66 3d ff 15 75 48 90 00 } //01 00 
		$a_01_2 = {77 71 3d 25 73 26 77 66 3d 25 73 26 77 73 3d 25 64 26 62 62 3d 25 73 26 64 3d 67 26 79 78 3d } //01 00  wq=%s&wf=%s&ws=%d&bb=%s&d=g&yx=
		$a_01_3 = {64 3d 72 77 26 62 62 3d 25 73 26 77 66 3d 25 73 26 79 78 3d 25 73 } //01 00  d=rw&bb=%s&wf=%s&yx=%s
		$a_01_4 = {79 78 3d 68 6f 73 74 26 77 6a 6d 3d 25 73 26 73 73 3d 25 73 } //00 00  yx=host&wjm=%s&ss=%s
	condition:
		any of ($a_*)
 
}