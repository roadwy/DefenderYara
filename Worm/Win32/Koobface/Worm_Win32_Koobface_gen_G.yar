
rule Worm_Win32_Koobface_gen_G{
	meta:
		description = "Worm:Win32/Koobface.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 61 63 74 69 6f 6e 3d 70 70 67 65 6e 26 61 3d 25 64 26 76 3d 25 73 26 70 69 64 3d 25 73 26 63 6e 74 3d 25 64 } //1 %s?action=ppgen&a=%d&v=%s&pid=%s&cnt=%d
		$a_01_1 = {25 73 3f 61 63 74 69 6f 6e 3d 6d 64 35 67 65 6e 26 75 72 6c 3d 25 73 26 72 65 71 68 61 73 68 3d 25 73 26 72 65 73 68 61 73 68 3d 25 73 26 76 3d 30 31 } //1 %s?action=md5gen&url=%s&reqhash=%s&reshash=%s&v=01
		$a_01_2 = {25 73 3f 76 3d 31 26 61 63 74 69 6f 6e 3d 70 61 73 73 67 65 6e 26 6c 3d 25 73 26 70 3d 25 73 } //1 %s?v=1&action=passgen&l=%s&p=%s
		$a_01_3 = {25 73 3f 61 63 74 69 6f 6e 3d 62 61 6e 75 72 6c 67 65 6e 26 76 3d 25 73 26 62 61 6e 5f 75 72 6c 3d 25 73 } //1 %s?action=banurlgen&v=%s&ban_url=%s
		$a_01_4 = {25 73 5c 7a 70 73 6b 6f 6e 5f 25 64 2e 65 78 65 } //1 %s\zpskon_%d.exe
		$a_01_5 = {66 65 65 64 77 61 6c 6c 5f 77 69 74 68 5f 63 6f 6d 70 6f 73 65 72 00 } //1
		$a_00_6 = {2f 00 72 00 6f 00 61 00 64 00 62 00 6c 00 6f 00 63 00 6b 00 2f 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}