
rule PWS_Win32_OnLineGames_KY{
	meta:
		description = "PWS:Win32/OnLineGames.KY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 c2 61 88 14 3e 46 83 fe 09 7c ea 68 ?? ?? ?? ?? 57 c6 04 3e 00 ff 15 } //1
		$a_02_1 = {71 71 70 63 74 72 61 79 2e 65 78 65 [0-05] 72 61 76 6d 6f 6e 64 2e 65 78 65 00 33 36 30 74 72 61 79 2e 65 78 65 00 25 73 20 2f 63 20 64 65 6c 20 25 73 00 } //1
		$a_02_2 = {6f 00 76 00 65 00 72 00 [0-0a] 49 00 49 00 4f 00 4c 00 53 00 50 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule PWS_Win32_OnLineGames_KY_2{
	meta:
		description = "PWS:Win32/OnLineGames.KY,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 10 fe cb 88 1c 10 40 3b c1 7c f3 } //2
		$a_02_1 = {26 72 61 6e 6b 3d [0-05] 26 70 77 64 3d [0-05] 26 75 73 65 72 6e 61 6d 65 3d [0-05] 26 73 65 72 76 65 72 3d } //2
		$a_02_2 = {26 6d 61 63 3d [0-05] 26 7a 68 61 6e 62 69 61 6f 3d [0-05] 26 63 68 61 6e 6e 65 6c 3d } //2
		$a_00_3 = {62 61 73 69 63 69 6e 66 6f 2e 61 73 70 78 3f 61 72 65 61 3d } //1 basicinfo.aspx?area=
		$a_00_4 = {70 61 72 61 6d 2e 61 73 70 78 3f 75 73 65 72 6e 61 6d 65 3d } //1 param.aspx?username=
	condition:
		((#a_01_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}