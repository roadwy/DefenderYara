
rule PWS_Win32_OnLineGames_AL{
	meta:
		description = "PWS:Win32/OnLineGames.AL,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 00 50 8d 90 01 03 6a 04 51 56 ff d3 8b 54 24 10 6a 00 81 c2 f8 00 00 00 6a 00 52 56 ff d7 33 c0 8d 90 01 03 89 90 01 03 8d 90 01 03 89 90 01 03 50 51 6a 08 52 56 66 90 01 04 ff d3 8b 90 01 03 8b 90 01 03 40 00 3d 32 54 76 98 90 00 } //5
		$a_00_1 = {77 6f 77 2e 65 78 65 } //1 wow.exe
		$a_00_2 = {71 71 2e 65 78 65 } //1 qq.exe
		$a_00_3 = {69 6e 66 65 63 74 69 6f 6e 20 73 74 61 72 74 65 64 } //1 infection started
		$a_00_4 = {2f 63 20 20 64 65 6c 20 43 3a 5c 6d 79 61 70 70 2e 65 78 65 20 3e 20 6e 75 6c } //1 /c  del C:\myapp.exe > nul
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=8
 
}