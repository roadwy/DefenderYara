
rule PWS_Win32_OnLineGames_AR{
	meta:
		description = "PWS:Win32/OnLineGames.AR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_02_0 = {5c 73 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 [0-10] 5c 73 79 73 74 65 6d 33 32 5c 77 64 [0-06] 2e 64 6c 6c 2c 48 6f 6f 6b 00 } //2
		$a_00_1 = {5c 73 79 73 74 65 6d 33 32 00 41 73 6b 54 61 6f 00 00 53 74 61 72 74 77 64 00 53 74 61 72 74 00 00 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //2
		$a_02_2 = {68 20 00 cc 00 68 02 01 00 00 68 a8 00 00 00 55 6a 19 56 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? be ?? ?? ?? ?? 68 80 00 00 00 56 ff d5 } //1
		$a_00_3 = {26 41 63 63 6f 75 6e 74 3d 00 00 00 26 43 61 73 68 3d 00 00 26 52 61 6e 6b 3d 00 00 26 52 6f 6c 65 3d 00 00 26 59 75 61 6e 62 61 6f 3d } //2
		$a_00_4 = {26 53 65 72 76 65 72 3d 00 00 00 00 62 61 73 69 63 69 6e 66 6f 2e 61 73 70 78 3f 41 72 65 61 3d 00 00 00 00 50 4f 53 54 20 00 00 00 79 6f 75 20 61 72 65 20 6b 69 63 6b 65 64 } //2
		$a_01_5 = {d1 b0 cf c9 ce ca b5 c0 00 } //1
		$a_01_6 = {d5 cc bd a3 b3 a4 b8 e8 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}