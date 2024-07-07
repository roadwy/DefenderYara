
rule TrojanDownloader_Win32_Dembr_B{
	meta:
		description = "TrojanDownloader:Win32/Dembr.B,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 f9 2b c2 3d b8 0b 00 00 77 44 8b c3 56 33 c9 8d 70 01 8a 10 40 84 d2 75 f9 2b c6 74 30 } //10
		$a_01_1 = {54 47 49 49 54 47 4d 31 47 53 45 52 3a 3c 34 39 31 4d 52 50 58 3a 36 3d 34 35 34 31 35 47 51 50 4d 51 36 34 35 36 } //1 TGIITGM1GSER:<491MRPX:6=45415GQPMQ6456
		$a_01_2 = {57 5d 57 58 49 51 60 47 79 76 76 69 72 78 47 73 72 78 76 73 70 57 69 78 60 77 69 76 7a 6d 67 69 77 60 57 67 6c 69 68 79 70 69 } //1 W]WXIQ`GyvvirxGsrxvspWix`wivzmgiw`Wglihypi
		$a_01_3 = {48 69 74 69 72 69 72 67 7d } //1 Hitirirg}
		$a_01_4 = {57 69 76 7a 6d 67 69 51 65 6d 72 00 6d 72 6d 32 68 70 70 7d } //1 楗究杭兩浥r牭㉭灨絰
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}