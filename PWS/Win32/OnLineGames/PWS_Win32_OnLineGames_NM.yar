
rule PWS_Win32_OnLineGames_NM{
	meta:
		description = "PWS:Win32/OnLineGames.NM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {83 fe 36 7e 05 83 ee 32 eb 03 83 c6 05 8d 4c 24 08 51 ff d7 8b 54 24 14 81 e2 ff ff 00 00 3b d6 75 eb } //2
		$a_01_1 = {eb 03 8b d6 46 8a 0c 07 32 0c 1a 40 4d 88 48 ff 75 e4 } //2
		$a_03_2 = {7e 24 56 8b 74 24 90 01 01 57 8d 3c 16 8b 74 24 90 01 01 8a 14 07 88 14 30 40 3b c1 7c f5 90 00 } //2
		$a_01_3 = {68 70 69 67 5f 57 53 32 2e 64 61 74 } //1 hpig_WS2.dat
		$a_01_4 = {26 74 79 70 65 3d 00 00 64 61 74 61 3d } //1
		$a_01_5 = {5c 68 75 6e 73 61 34 2e 64 6c 6c } //1 \hunsa4.dll
		$a_00_6 = {4d 49 42 41 4f 2e 62 6d 70 } //1 MIBAO.bmp
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}