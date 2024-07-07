
rule PWS_Win32_Frethog_NL{
	meta:
		description = "PWS:Win32/Frethog.NL,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 76 75 69 6a 68 4b 7a 2e 65 78 65 } //10 \MvuijhKz.exe
		$a_01_1 = {2e 77 6f 61 69 33 31 30 2e 63 6f 6d 2f 3f 64 6f 3d 70 6f 73 74 26 75 3d 25 73 26 6d 3d 25 73 26 63 3d 25 64 26 73 3d 25 64 26 72 3d 25 73 26 76 3d 25 73 26 70 3d 25 73 } //10 .woai310.com/?do=post&u=%s&m=%s&c=%d&s=%d&r=%s&v=%s&p=%s
		$a_01_2 = {66 69 66 61 30 37 2e 65 78 65 } //1 fifa07.exe
		$a_01_3 = {67 74 61 33 2e 65 78 65 } //1 gta3.exe
		$a_01_4 = {6c 65 66 74 34 64 65 61 64 2e 65 78 65 } //1 left4dead.exe
		$a_01_5 = {6e 62 61 32 6b 31 30 2e 65 78 65 } //1 nba2k10.exe
		$a_01_6 = {77 6f 77 2e 65 78 65 } //1 wow.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=25
 
}