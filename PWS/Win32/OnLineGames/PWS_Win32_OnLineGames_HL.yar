
rule PWS_Win32_OnLineGames_HL{
	meta:
		description = "PWS:Win32/OnLineGames.HL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {50 4f 53 54 20 25 73 3f 70 61 74 68 3d 25 73 } //1 POST %s?path=%s
		$a_01_1 = {25 73 3f 61 63 74 69 6f 6e 3d 67 65 74 6d 61 26 75 3d 25 73 } //1 %s?action=getma&u=%s
		$a_01_2 = {25 73 3f 61 63 74 69 6f 6e 3d 73 65 74 6d 70 26 6d 70 3d 25 73 26 75 3d 25 73 } //1 %s?action=setmp&mp=%s&u=%s
		$a_00_3 = {6d 6f 6e 65 79 3a 25 64 } //1 money:%d
		$a_01_4 = {26 6d 3d 00 26 70 3d 00 26 75 3d 00 3f 69 64 3d 00 } //1
		$a_00_5 = {75 73 65 72 3a 25 73 20 70 61 73 73 3a 25 73 } //1 user:%s pass:%s
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}
rule PWS_Win32_OnLineGames_HL_2{
	meta:
		description = "PWS:Win32/OnLineGames.HL,SIGNATURE_TYPE_PEHSTR,14 00 14 00 0a 00 00 "
		
	strings :
		$a_01_0 = {4d 41 50 4c 45 53 54 4f 52 59 2e 45 58 45 } //10 MAPLESTORY.EXE
		$a_01_1 = {50 4f 53 54 20 25 73 3f 70 61 74 68 3d 25 73 } //2 POST %s?path=%s
		$a_01_2 = {49 6e 73 74 61 6c 6c 48 4f 4f 4b } //2 InstallHOOK
		$a_01_3 = {25 73 3f 61 63 74 69 6f 6e 3d 67 65 74 6d 61 26 75 3d 25 73 } //2 %s?action=getma&u=%s
		$a_01_4 = {67 65 74 6d 6f 6e 65 79 65 76 65 6e 74 } //1 getmoneyevent
		$a_01_5 = {67 65 74 70 61 73 73 65 76 65 6e 74 } //1 getpassevent
		$a_01_6 = {67 6f 74 20 6d 6f 6e 65 79 3a 25 73 } //1 got money:%s
		$a_01_7 = {69 6e 20 67 65 74 6d 6f 6e 65 79 20 74 68 72 65 61 64 } //1 in getmoney thread
		$a_01_8 = {75 70 6c 6f 61 64 20 25 73 } //1 upload %s
		$a_01_9 = {67 65 74 70 2e 61 73 70 } //1 getp.asp
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=20
 
}