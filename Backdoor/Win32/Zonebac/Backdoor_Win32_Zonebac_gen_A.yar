
rule Backdoor_Win32_Zonebac_gen_A{
	meta:
		description = "Backdoor:Win32/Zonebac.gen!A,SIGNATURE_TYPE_PEHSTR,0a 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 73 2f 25 64 2f 69 6e 2f 68 74 6d 6c 25 64 2e 68 74 6d 6c 3f } //2 http://%s/%d/in/html%d.html?
		$a_01_1 = {69 64 3d 25 64 26 61 69 64 3d 25 64 26 74 69 6d 65 3d 25 73 26 66 77 3d 25 64 26 76 3d 25 64 26 6d 3d 25 64 26 76 6d 3d 25 64 } //2 id=%d&aid=%d&time=%s&fw=%d&v=%d&m=%d&vm=%d
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 2f 25 64 2f 63 68 65 63 6b 69 6e 2e 70 68 70 3f } //2 http://%s/%d/checkin.php?
		$a_01_3 = {25 73 2f 64 72 66 25 64 2e 68 74 6d 6c } //1 %s/drf%d.html
		$a_01_4 = {47 80 3f 00 75 fa 33 c0 ab ab 6a 00 ff 75 08 ab } //1
		$a_01_5 = {59 8b ca d3 e0 83 c2 06 09 45 fc 47 83 fa 24 7c e5 } //1
		$a_01_6 = {8a 0c 01 3a 4c 24 04 74 08 40 83 f8 40 7c eb } //1
		$a_01_7 = {74 26 66 0f be 06 66 3b 45 0c 75 1c 0f bf 45 0c 50 ff 75 08 } //1
		$a_01_8 = {8b 4d fc 03 c8 8d 46 01 99 f7 fb 8b 45 08 89 4d f8 33 c9 83 45 fc 04 8a 0c 02 0f be 04 06 c1 e0 08 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}