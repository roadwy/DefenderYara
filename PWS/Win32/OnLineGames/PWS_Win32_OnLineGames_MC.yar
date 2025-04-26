
rule PWS_Win32_OnLineGames_MC{
	meta:
		description = "PWS:Win32/OnLineGames.MC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_01_0 = {2f 63 68 69 6e 61 2e 61 73 70 3f 30 6b 3d } //5 /china.asp?0k=
		$a_01_1 = {2f 71 71 2e 61 73 70 3f 51 51 4e 75 6d 62 65 72 3d } //2 /qq.asp?QQNumber=
		$a_01_2 = {43 3a 5c 42 30 30 54 2e 53 59 53 } //2 C:\B00T.SYS
		$a_01_3 = {3a 31 33 31 34 } //2 :1314
		$a_01_4 = {26 51 51 50 61 73 73 57 6f 72 64 3d } //2 &QQPassWord=
		$a_01_5 = {26 51 51 63 6c 75 62 3d } //2 &QQclub=
		$a_01_6 = {68 61 6e 67 61 6d 65 } //1 hangame
		$a_01_7 = {66 69 66 61 6f 6e 6c 69 6e 65 2e } //1 fifaonline.
		$a_01_8 = {61 6f 73 74 72 61 79 2e 65 78 65 } //1 aostray.exe
		$a_01_9 = {63 75 6c 74 75 72 65 6c 61 6e 64 2e 63 6f 2e 6b 72 } //1 cultureland.co.kr
		$a_01_10 = {68 61 70 70 79 6d 6f 6e 65 79 } //1 happymoney
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=10
 
}