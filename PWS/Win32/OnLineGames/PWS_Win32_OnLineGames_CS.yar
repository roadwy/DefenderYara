
rule PWS_Win32_OnLineGames_CS{
	meta:
		description = "PWS:Win32/OnLineGames.CS,SIGNATURE_TYPE_PEHSTR,1f 00 1e 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 75 73 65 72 3d 25 73 26 73 70 61 73 73 3d 25 73 26 73 65 72 69 61 6c 3d 25 73 26 73 65 72 4e 75 6d 3d 25 73 26 6e 61 6d 65 3d 25 73 26 6c 65 76 65 6c 3d 25 64 26 6d 6f 6e 65 79 3d 25 64 26 6c 69 6e 65 3d 25 73 26 62 6f 78 70 61 73 73 3d 25 73 } //0a 00 
		$a_01_1 = {33 c0 f2 ae f7 d1 2b f9 8d 95 d0 fd ff ff 8b c1 8b f7 8b fa 6a 2f c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8d 8d d7 fd ff ff 51 ff 15 } //05 00 
		$a_01_2 = {69 6e 73 74 61 6c 6c 48 6f 6f 6b } //05 00 
		$a_01_3 = {6d 73 67 43 61 6c 6c 42 61 63 6b 40 40 59 47 4a 48 49 4a 40 5a } //01 00 
		$a_01_4 = {75 6e 61 6d 65 2e 6e 6c 73 } //01 00 
		$a_01_5 = {6b 69 6c 6c 47 61 6d 65 } //01 00 
		$a_01_6 = {71 71 66 6f 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}