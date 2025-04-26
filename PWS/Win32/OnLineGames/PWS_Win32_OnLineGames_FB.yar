
rule PWS_Win32_OnLineGames_FB{
	meta:
		description = "PWS:Win32/OnLineGames.FB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {26 7a 74 3d 77 61 69 [0-04] 61 63 74 69 6f 6e 3d 75 70 26 75 3d [0-08] 26 7a 74 3d 73 75 63 63 6d 62 68 } //10
		$a_01_1 = {53 47 43 51 } //10 SGCQ
		$a_00_2 = {77 6d 67 6d 62 2e 61 73 70 } //1 wmgmb.asp
		$a_00_3 = {63 67 61 6d 65 61 73 64 66 67 68 } //1 cgameasdfgh
		$a_00_4 = {67 61 6d 65 71 77 65 72 74 79 } //1 gameqwerty
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=22
 
}