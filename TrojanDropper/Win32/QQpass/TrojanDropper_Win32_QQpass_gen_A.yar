
rule TrojanDropper_Win32_QQpass_gen_A{
	meta:
		description = "TrojanDropper:Win32/QQpass.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,46 00 37 00 30 00 00 "
		
	strings :
		$a_00_0 = {6e 70 6b 63 72 79 70 74 2e 73 79 73 } //1 npkcrypt.sys
		$a_00_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_00_2 = {46 69 72 73 74 20 52 75 6e } //2 First Run
		$a_00_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 24 } //2 C:\Windows\iexplore.$
		$a_00_4 = {45 78 70 6c 6f 72 65 72 2e 45 78 65 } //1 Explorer.Exe
		$a_00_5 = {2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 } //2 搮汬搀汬慣畮汮慯湤睯搀汬敧捴慬獳扯敪瑣搀汬敲楧瑳牥敳癲牥搀汬湵敲楧瑳牥敳癲牥
		$a_00_6 = {06 00 44 00 56 00 43 00 4c 00 41 00 4c 00 } //3
		$a_00_7 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //2 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_00_8 = {78 69 61 72 61 6e } //3 xiaran
		$a_00_9 = {4c 6f 67 69 6e 43 74 72 6c 2e 64 6c 6c } //2 LoginCtrl.dll
		$a_00_10 = {72 65 6a 6f 69 63 65 2e 64 6c 6c } //2 rejoice.dll
		$a_00_11 = {78 72 5f 44 6c 6c } //1 xr_Dll
		$a_00_12 = {78 72 5f 45 78 65 } //2 xr_Exe
		$a_00_13 = {61 69 78 69 61 72 61 6e } //2 aixiaran
		$a_00_14 = {8b d8 eb 01 6b 85 db 7e 15 80 7c 1e ff 5c 74 0e 80 7c 1e ff 3a 74 07 80 7c 1e ff 2f 75 e6 77 8b c6 } //5
		$a_00_15 = {73 76 77 8b fa 8b f0 8b c6 e8 ?? ?? ?? ?? 8b d8 eb 01 6b 85 db 7e 15 80 7c 1e ff 5c 74 0e 80 7c 1e ff 3a 74 07 80 7c 1e ff 2f 75 e6 77 8b c6 e8 ?? ?? ?? ?? 8b c8 2b cb 8d 73 01 8b c6 e8 ?? ?? ?? ?? 5f 5e 5b c3 } //5
		$a_00_16 = {73 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c 6a 01 e8 e2 ff ff ff } //5
		$a_00_17 = {75 2e 6a f4 53 e8 ?? ?? ff ff 3d b4 00 00 00 74 23 6a f0 53 e8 ?? ?? ff ff a8 20 75 17 6a 00 6a 00 68 d2 00 00 00 53 e8 ?? ?? ff ff } //5
		$a_00_18 = {4c 69 75 5f 4d 61 7a 69 } //5 Liu_Mazi
		$a_00_19 = {78 69 61 6e 67 } //5 xiang
		$a_00_20 = {54 48 6f 6f 6b 41 50 49 } //2 THookAPI
		$a_00_21 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //2 UnhookWindowsHookEx
		$a_00_22 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //2 SetWindowsHookExA
		$a_00_23 = {00 68 6f 6f 6b 2e 64 6c 6c } //2
		$a_00_24 = {4a 6d 70 48 6f 6f 6b 4f 6e } //2 JmpHookOn
		$a_00_25 = {7e 68 6f 6f 6b } //2 ~hook
		$a_02_26 = {53 6f 66 74 77 61 72 65 5c [0-03] 5c 51 51 42 65 74 61 33 20 48 6f 6f 6b 65 72 } //15
		$a_00_27 = {30 38 33 31 35 43 31 41 2d 39 42 41 39 2d 34 42 37 43 2d 41 34 33 32 2d 32 36 38 38 35 46 37 38 44 46 32 38 } //10 08315C1A-9BA9-4B7C-A432-26885F78DF28
		$a_00_28 = {51 51 32 30 30 35 5f 48 6f 6f 6b 65 72 5f 48 65 61 64 } //10 QQ2005_Hooker_Head
		$a_00_29 = {51 71 48 65 6c 70 65 72 44 6c 6c 2e 44 6c 6c } //10 QqHelperDll.Dll
		$a_00_30 = {51 51 4e 75 6d 62 65 72 3d } //10 QQNumber=
		$a_00_31 = {00 71 71 2e 45 78 65 } //5
		$a_00_32 = {26 51 51 50 61 73 73 57 6f 72 64 3d } //10 &QQPassWord=
		$a_00_33 = {51 51 4c 69 73 74 } //5 QQList
		$a_00_34 = {68 74 74 70 3a 2f 2f 6a 75 6d 70 2e 71 71 2e 63 6f 6d 2f 63 6c 69 65 6e 74 75 72 6c 5f } //5 http://jump.qq.com/clienturl_
		$a_00_35 = {48 45 4c 4f 20 } //2 HELO 
		$a_00_36 = {41 55 54 48 20 4c 4f 47 49 4e } //2 AUTH LOGIN
		$a_00_37 = {4d 41 49 4c 20 46 52 4f 4d 3a 20 3c } //2 MAIL FROM: <
		$a_00_38 = {52 43 50 54 20 54 4f 3a 20 3c } //1 RCPT TO: <
		$a_00_39 = {46 72 6f 6d 3a 20 3c } //1 From: <
		$a_00_40 = {54 6f 3a 20 3c } //1 To: <
		$a_00_41 = {53 75 62 6a 65 63 74 3a 20 } //1 Subject: 
		$a_00_42 = {64 61 74 61 0d 0a 00 00 ff ff ff ff ?? 00 00 00 66 72 6f 6d 3a 20 3c } //5
		$a_00_43 = {48 54 54 50 2f 31 2e 30 } //1 HTTP/1.0
		$a_00_44 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //1 Content-Type: application/x-www-form-urlencoded
		$a_00_45 = {ff ff ff ff 07 00 00 00 68 74 74 70 3a 2f 2f 00 } //2
		$a_00_46 = {41 63 63 65 70 74 3a 20 2a 2f 2a 00 48 54 54 50 2f 31 2e 30 00 00 00 00 50 4f 53 54 00 00 00 00 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //2
		$a_00_47 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //5 SOFTWARE\Borland\Delphi\RTL
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*2+(#a_00_6  & 1)*3+(#a_00_7  & 1)*2+(#a_00_8  & 1)*3+(#a_00_9  & 1)*2+(#a_00_10  & 1)*2+(#a_00_11  & 1)*1+(#a_00_12  & 1)*2+(#a_00_13  & 1)*2+(#a_00_14  & 1)*5+(#a_00_15  & 1)*5+(#a_00_16  & 1)*5+(#a_00_17  & 1)*5+(#a_00_18  & 1)*5+(#a_00_19  & 1)*5+(#a_00_20  & 1)*2+(#a_00_21  & 1)*2+(#a_00_22  & 1)*2+(#a_00_23  & 1)*2+(#a_00_24  & 1)*2+(#a_00_25  & 1)*2+(#a_02_26  & 1)*15+(#a_00_27  & 1)*10+(#a_00_28  & 1)*10+(#a_00_29  & 1)*10+(#a_00_30  & 1)*10+(#a_00_31  & 1)*5+(#a_00_32  & 1)*10+(#a_00_33  & 1)*5+(#a_00_34  & 1)*5+(#a_00_35  & 1)*2+(#a_00_36  & 1)*2+(#a_00_37  & 1)*2+(#a_00_38  & 1)*1+(#a_00_39  & 1)*1+(#a_00_40  & 1)*1+(#a_00_41  & 1)*1+(#a_00_42  & 1)*5+(#a_00_43  & 1)*1+(#a_00_44  & 1)*1+(#a_00_45  & 1)*2+(#a_00_46  & 1)*2+(#a_00_47  & 1)*5) >=55
 
}