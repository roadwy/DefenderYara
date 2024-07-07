
rule PWS_Win32_OnLineGames_KD{
	meta:
		description = "PWS:Win32/OnLineGames.KD,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69 70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 3b 20 62 6f 75 6e 64 61 72 79 3d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 37 64 62 66 61 32 39 31 62 30 33 39 30 } //4 Content-Type: multipart/form-data; boundary=---------------------------7dbfa291b0390
		$a_01_1 = {25 73 3f 73 3d 25 73 26 61 3d 25 73 26 75 3d 25 73 26 70 3d 25 73 26 6e 3d 25 73 26 6c 76 3d 25 64 26 67 3d 25 64 26 78 67 3d 25 64 26 79 3d 25 64 26 25 73 3d 25 73 26 25 73 3d 25 73 26 25 73 3d 25 73 26 6d 62 68 3d 25 64 26 6c 3d 25 73 26 73 6c 3d 25 73 } //4 %s?s=%s&a=%s&u=%s&p=%s&n=%s&lv=%d&g=%d&xg=%d&y=%d&%s=%s&%s=%s&%s=%s&mbh=%d&l=%s&sl=%s
		$a_01_2 = {5e 24 5e 53 65 72 69 61 6c 4e 75 6d } //3 ^$^SerialNum
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3) >=11
 
}