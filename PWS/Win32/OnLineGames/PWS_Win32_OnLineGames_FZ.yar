
rule PWS_Win32_OnLineGames_FZ{
	meta:
		description = "PWS:Win32/OnLineGames.FZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 33 db 80 60 06 00 8b ca 88 50 01 8a de c1 e9 10 33 d2 88 58 02 8a d5 c6 00 ea 88 48 03 88 50 04 c6 40 05 1b 5b } //2
		$a_03_1 = {75 4c 53 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 53 8d 45 0f ff 35 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 14 80 7d 0f e8 75 27 } //2
		$a_01_2 = {25 73 3f 75 73 3d 25 73 26 70 73 3d 25 73 26 6c 76 3d 25 73 26 73 65 3d 25 73 26 71 75 3d 25 73 26 6f 73 3d 25 73 } //1 %s?us=%s&ps=%s&lv=%s&se=%s&qu=%s&os=%s
		$a_01_3 = {25 73 3f 75 3d 25 73 26 6d 3d 25 73 26 75 72 6c 3d 25 73 26 61 63 74 69 6f 6e 3d 25 73 } //1 %s?u=%s&m=%s&url=%s&action=%s
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}