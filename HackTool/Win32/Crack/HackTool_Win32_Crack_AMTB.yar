
rule HackTool_Win32_Crack_AMTB{
	meta:
		description = "HackTool:Win32/Crack!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0b 00 00 "
		
	strings :
		$a_80_0 = {53 65 6c 65 6e 69 74 65 2e 70 64 62 } //Selenite.pdb  1
		$a_80_1 = {53 65 6c 65 6e 69 74 65 46 61 6b 65 47 72 61 62 49 50 47 75 6e 2e 74 78 74 } //SeleniteFakeGrabIPGun.txt  1
		$a_80_2 = {53 65 6c 65 6e 69 74 65 47 72 61 62 49 44 47 75 6e 2e 74 78 74 } //SeleniteGrabIDGun.txt  1
		$a_80_3 = {53 65 6c 65 6e 69 74 65 52 6f 6f 6d 49 6e 66 6f 2e 74 78 74 } //SeleniteRoomInfo.txt  1
		$a_80_4 = {53 65 6c 65 6e 69 74 65 2e 64 6c 6c } //Selenite.dll  1
		$a_80_5 = {68 74 74 70 73 3a 2f 2f 69 69 64 6b 2e 6f 6e 6c 69 6e 65 } //https://iidk.online  1
		$a_02_6 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 63 00 61 00 74 00 62 00 6f 00 78 00 2e 00 6d 00 6f 00 65 00 2f 00 [0-0f] 2e 00 6d 00 70 00 33 00 } //1
		$a_02_7 = {68 74 74 70 73 3a 2f 2f 66 69 6c 65 73 2e 63 61 74 62 6f 78 2e 6d 6f 65 2f [0-0f] 2e 6d 70 33 } //1
		$a_80_8 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_9 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_10 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_02_6  & 1)*1+(#a_02_7  & 1)*1+(#a_80_8  & 1)*-100+(#a_80_9  & 1)*-100+(#a_80_10  & 1)*-100) >=7
 
}