
rule Trojan_Win32_Dridex_DW_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {68 52 65 61 63 68 61 70 70 65 61 72 2e 31 35 32 39 43 68 72 6f 6d 69 75 6d 46 61 63 65 62 6f 6f 6b } //3 hReachappear.1529ChromiumFacebook
		$a_81_1 = {70 32 35 6d 65 6e 75 2c 71 75 69 63 6b 65 72 2c 47 77 69 6c 6c 69 65 73 69 74 65 73 64 65 78 74 65 72 61 6e 64 } //3 p25menu,quicker,Gwilliesitesdexterand
		$a_81_2 = {63 61 6e 61 64 61 48 79 77 69 6e 73 74 6f 6e 62 65 66 6f 72 65 } //3 canadaHywinstonbefore
		$a_81_3 = {42 65 74 61 74 72 65 65 6b 69 6e 67 33 73 65 65 63 65 73 65 73 6f 65 76 69 6e 67 2e 31 32 33 66 6f 72 58 65 6d 65 74 69 66 } //3 Betatreeking3seecesesoeving.123forXemetif
		$a_81_4 = {43 68 65 65 6d 65 65 68 65 72 69 6e 69 74 69 61 74 65 64 79 37 37 37 37 37 37 62 79 45 } //3 Cheemeeherinitiatedy777777byE
		$a_81_5 = {53 48 45 6e 75 6d 65 72 61 74 65 55 6e 72 65 61 64 4d 61 69 6c 41 63 63 6f 75 6e 74 73 57 } //3 SHEnumerateUnreadMailAccountsW
		$a_81_6 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } //3 FFPGGLBM.pdb
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_DW_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0c 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e } //2 InternetOpen
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //2 VirtualProtect
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //2 VirtualAlloc
		$a_01_3 = {68 74 74 70 3a 2f 2f } //2 http://
		$a_01_4 = {74 65 73 74 2e 62 68 42 6c 33 36 30 2e 63 6f } //2 test.bhBl360.co
		$a_01_5 = {6d 2f 30 30 31 2f 70 75 70 70 65 } //2 m/001/puppe
		$a_01_6 = {2e 65 78 65 59 } //2 .exeY
		$a_01_7 = {48 54 54 50 2f 31 2e 31 } //2 HTTP/1.1
		$a_01_8 = {53 68 78 4a 77 70 4c 53 68 78 4a 77 70 4c 53 68 78 4a 77 70 4c } //2 ShxJwpLShxJwpLShxJwpL
		$a_01_9 = {75 61 33 6c 77 63 79 31 57 75 61 33 6c 77 63 79 31 57 75 61 33 6c 77 63 79 31 } //2 ua3lwcy1Wua3lwcy1Wua3lwcy1
		$a_01_10 = {67 64 71 36 51 53 71 62 56 37 6d 56 70 52 67 64 71 36 51 53 71 62 56 37 6d 56 70 52 67 64 71 36 51 53 71 62 56 37 6d 56 70 52 } //2 gdq6QSqbV7mVpRgdq6QSqbV7mVpRgdq6QSqbV7mVpR
		$a_01_11 = {67 67 6f 39 37 31 67 67 6f 39 37 31 38 37 4b 41 79 52 70 47 55 72 41 77 4e 71 } //2 ggo971ggo97187KAyRpGUrAwNq
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2) >=24
 
}