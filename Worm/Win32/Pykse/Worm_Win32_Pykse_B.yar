
rule Worm_Win32_Pykse_B{
	meta:
		description = "Worm:Win32/Pykse.B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 45 54 20 55 53 45 52 53 54 41 54 55 53 } //1 SET USERSTATUS
		$a_01_1 = {55 53 45 52 53 } //1 USERS
		$a_01_2 = {4f 4e 4c 49 4e 45 53 54 41 54 55 53 } //1 ONLINESTATUS
		$a_01_3 = {53 45 41 52 43 48 20 46 52 49 45 4e 44 53 } //1 SEARCH FRIENDS
		$a_01_4 = {53 6b 79 70 65 2d 41 50 49 2d 43 74 72 6c } //2 Skype-API-Ctrl
		$a_01_5 = {53 6b 79 70 65 43 6f 6e 74 72 6f 6c 41 50 49 } //2 SkypeControlAPI
		$a_01_6 = {53 6b 79 70 65 20 57 6f 72 6d } //3 Skype Worm
		$a_00_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_8 = {4d 45 53 53 41 47 45 20 25 73 20 25 73 } //3 MESSAGE %s %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*3+(#a_00_7  & 1)*1+(#a_01_8  & 1)*3) >=12
 
}