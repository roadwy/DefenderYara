
rule PWS_Win32_Wowsteal_BC{
	meta:
		description = "PWS:Win32/Wowsteal.BC,SIGNATURE_TYPE_PEHSTR,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 44 57 } //2 rundll32.exe %s,DW
		$a_01_1 = {77 6f 77 2e 65 78 65 } //2 wow.exe
		$a_01_2 = {4c 69 75 4d 61 7a 69 } //2 LiuMazi
		$a_01_3 = {68 74 74 70 3a 2f 2f 39 38 2e 31 32 36 2e 34 38 2e 31 32 34 2f 77 6f 77 70 69 6e 2f 6d 61 69 6c 2e 61 73 70 } //2 http://98.126.48.124/wowpin/mail.asp
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 31 31 31 31 2e 63 6f 6d 2f 70 6f 73 74 2e 61 73 70 } //1 http://www.1111.com/post.asp
		$a_01_5 = {2e 63 6f 6d 2f 6d 69 62 61 6f 2e 61 73 70 } //1 .com/mibao.asp
		$a_01_6 = {68 74 74 70 3a 2f 2f 67 6d 6e 62 2e 69 6e 66 6f 2f 62 62 71 63 63 2f 6d 61 69 6c 2e 61 73 70 } //1 http://gmnb.info/bbqcc/mail.asp
		$a_01_7 = {25 73 3f 66 31 3d 67 65 74 70 6f 73 26 66 32 3d 25 73 } //1 %s?f1=getpos&f2=%s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=9
 
}