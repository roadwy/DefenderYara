
rule PWS_Win32_QQpass_gen_A{
	meta:
		description = "PWS:Win32/QQpass.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,ffffffaa 00 ffffff96 00 28 00 00 "
		
	strings :
		$a_00_0 = {75 6e 68 6f 6f 6b 77 69 6e 64 6f 77 73 68 6f 6f 6b 65 78 } //5 unhookwindowshookex
		$a_01_1 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //5 SetWindowsHookExA
		$a_00_2 = {63 61 6c 6c 6e 65 78 74 68 6f 6f 6b 65 78 } //5 callnexthookex
		$a_01_3 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //5 InternetReadFile
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //5 InternetOpenUrlA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //5 InternetOpenA
		$a_01_6 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 } //5 InternetCloseHandle
		$a_00_7 = {68 6f 6f 6b 2e 64 6c 6c } //10 hook.dll
		$a_01_8 = {4d 73 67 48 6f 6f 6b 4f 66 66 } //10 MsgHookOff
		$a_01_9 = {4d 73 67 48 6f 6f 6b 4f 6e } //10 MsgHookOn
		$a_01_10 = {54 48 6f 6f 6b 41 50 49 } //5 THookAPI
		$a_00_11 = {45 78 70 6c 6f 72 65 72 2e 45 78 65 } //3 Explorer.Exe
		$a_00_12 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 24 } //6 C:\Windows\iexplore.$
		$a_01_13 = {56 65 72 43 4c 53 49 44 2e 65 78 65 } //2 VerCLSID.exe
		$a_00_14 = {41 63 63 65 70 74 3a 20 2a 2f 2a } //1 Accept: */*
		$a_00_15 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //1 Content-Type: application/x-www-form-urlencoded
		$a_00_16 = {23 33 32 37 37 30 } //1 #32770
		$a_00_17 = {48 54 54 50 2f 31 2e 30 } //1 HTTP/1.0
		$a_01_18 = {6e 70 6b 63 72 79 70 74 2e 73 79 73 } //5 npkcrypt.sys
		$a_01_19 = {68 74 74 70 3a 2f 2f 6a 75 6d 70 2e 71 71 2e 63 6f 6d 2f 63 6c 69 65 6e 74 75 72 6c 5f 31 35 } //10 http://jump.qq.com/clienturl_15
		$a_01_20 = {68 74 74 70 3a 2f 2f 6a 75 6d 70 2e 71 71 2e 63 6f 6d 2f 63 6c 69 65 6e 74 75 72 6c 5f 31 30 30 3f 63 6c 69 65 6e 74 75 69 6e 3d } //15 http://jump.qq.com/clienturl_100?clientuin=
		$a_01_21 = {4c 6f 67 69 6e 43 74 72 6c 2e 64 6c 6c } //10 LoginCtrl.dll
		$a_01_22 = {51 71 2e 45 78 65 } //5 Qq.Exe
		$a_01_23 = {51 71 4c 69 73 74 } //5 QqList
		$a_01_24 = {51 71 47 61 6d 65 2e 45 78 65 } //5 QqGame.Exe
		$a_01_25 = {54 65 6e 63 65 6e 74 5f 51 51 54 6f 6f 6c 42 61 72 } //5 Tencent_QQToolBar
		$a_01_26 = {54 65 6e 63 65 6e 74 5f 51 51 42 61 72 } //5 Tencent_QQBar
		$a_01_27 = {71 71 6a 64 64 45 78 65 } //5 qqjddExe
		$a_01_28 = {71 71 6a 64 64 44 6c 6c } //5 qqjddDll
		$a_01_29 = {77 61 69 6f 7a 6f 6e 67 73 68 69 63 68 61 6e 67 67 65 68 6f 6e 67 77 6f 6e 61 68 73 6f 75 67 65 68 61 6f 78 69 61 6e 67 7a 68 65 79 61 6e 67 63 68 61 6e 67 64 65 77 6f 64 65 67 75 78 69 61 6e 67 7a 61 69 79 75 61 6e 66 61 6e 67 } //10 waiozongshichanggehongwonahsougehaoxiangzheyangchangdewodeguxiangzaiyuanfang
		$a_01_30 = {74 69 61 6e 68 65 69 68 65 69 74 69 6f 6f 74 69 61 6e 74 69 61 6e 64 6f 75 79 61 6f 6e 69 61 69 77 6f 64 65 78 69 6e 73 69 79 6f 75 6e 69 63 61 69 62 75 79 61 6f 77 65 6e 77 6f 63 6f 6e 67 6e 61 6c 69 6c 61 69 } //10 tianheiheitiootiantiandouyaoniaiwodexinsiyounicaibuyaowenwocongnalilai
		$a_01_31 = {69 6e 67 64 65 73 68 69 68 6f 75 } //10 ingdeshihou
		$a_01_32 = {26 63 6c 69 65 6e 74 6b 65 79 3d } //3 &clientkey=
		$a_01_33 = {57 65 62 4d 61 69 6c } //2 WebMail
		$a_01_34 = {6e 61 6d 65 3d 22 75 69 6e 22 } //3 name="uin"
		$a_01_35 = {76 61 6c 75 65 3d 22 } //2 value="
		$a_01_36 = {6e 61 6d 65 3d 22 6b 22 } //3 name="k"
		$a_01_37 = {26 55 69 6e 3d } //3 &Uin=
		$a_01_38 = {6d 61 69 6c 2e 71 71 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 6c 6f 67 69 6e } //2 mail.qq.com/cgi-bin/login
		$a_01_39 = {68 74 74 70 3a 2f 2f 66 6c 61 73 68 2e 63 68 69 6e 61 72 65 6e 2e 63 6f 6d 2f 69 70 2f 69 70 2e 70 68 70 } //2 http://flash.chinaren.com/ip/ip.php
	condition:
		((#a_00_0  & 1)*5+(#a_01_1  & 1)*5+(#a_00_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_00_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*5+(#a_00_11  & 1)*3+(#a_00_12  & 1)*6+(#a_01_13  & 1)*2+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_01_18  & 1)*5+(#a_01_19  & 1)*10+(#a_01_20  & 1)*15+(#a_01_21  & 1)*10+(#a_01_22  & 1)*5+(#a_01_23  & 1)*5+(#a_01_24  & 1)*5+(#a_01_25  & 1)*5+(#a_01_26  & 1)*5+(#a_01_27  & 1)*5+(#a_01_28  & 1)*5+(#a_01_29  & 1)*10+(#a_01_30  & 1)*10+(#a_01_31  & 1)*10+(#a_01_32  & 1)*3+(#a_01_33  & 1)*2+(#a_01_34  & 1)*3+(#a_01_35  & 1)*2+(#a_01_36  & 1)*3+(#a_01_37  & 1)*3+(#a_01_38  & 1)*2+(#a_01_39  & 1)*2) >=150
 
}