
rule TrojanClicker_Win32_Yeeha_A{
	meta:
		description = "TrojanClicker:Win32/Yeeha.A,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 09 00 00 "
		
	strings :
		$a_02_0 = {62 00 61 00 69 00 64 00 75 00 2e 00 63 00 6f 00 6d 90 02 30 63 6c 69 63 6b 90 02 30 48 69 74 65 6d 90 00 } //10
		$a_00_1 = {4f 6e 47 65 74 50 61 73 73 77 6f 72 64 } //10 OnGetPassword
		$a_00_2 = {67 65 74 78 79 2e 61 73 70 3f 75 3d } //1 getxy.asp?u=
		$a_00_3 = {74 61 72 67 65 74 3d 22 5f 70 61 72 65 6e 74 22 3e 31 3c 2f 61 3e } //1 target="_parent">1</a>
		$a_00_4 = {67 65 74 75 72 6c 69 70 2e 61 73 70 3f 67 6f 3d } //1 geturlip.asp?go=
		$a_00_5 = {67 65 74 6e 6f 2e 61 73 70 3f 67 6f 3d } //1 getno.asp?go=
		$a_00_6 = {67 65 74 75 72 6c 2e 61 73 70 3f 75 3d } //1 geturl.asp?u=
		$a_00_7 = {67 65 74 6e 6f 2e 61 73 70 3f 75 3d } //1 getno.asp?u=
		$a_00_8 = {68 74 74 70 3a 2f 2f 77 70 61 2e 71 71 2e 63 6f 6d } //10 http://wpa.qq.com
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*10) >=33
 
}