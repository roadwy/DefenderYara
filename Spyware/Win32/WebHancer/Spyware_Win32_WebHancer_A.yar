
rule Spyware_Win32_WebHancer_A{
	meta:
		description = "Spyware:Win32/WebHancer.A,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 68 69 65 73 68 6d 2e 64 6c 6c } //3 whieshm.dll
		$a_01_1 = {77 68 41 67 65 6e 74 2e 65 78 65 } //3 whAgent.exe
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 77 65 62 48 61 6e 63 65 72 } //3 Software\webHancer
		$a_01_3 = {77 68 69 65 68 6c 70 72 2e 64 6c 6c } //3 whiehlpr.dll
		$a_01_4 = {77 68 69 65 64 63 2e 53 54 41 54 49 43 } //6 whiedc.STATIC
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*6) >=15
 
}
rule Spyware_Win32_WebHancer_A_2{
	meta:
		description = "Spyware:Win32/WebHancer.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 68 69 65 73 68 6d 2e 64 6c 6c } //2 whieshm.dll
		$a_01_1 = {77 68 41 67 65 6e 74 2e 65 78 65 } //2 whAgent.exe
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 77 65 62 48 61 6e 63 65 72 } //2 Software\webHancer
		$a_01_3 = {77 68 69 65 64 63 2e 64 6c 6c } //2 whiedc.dll
		$a_01_4 = {43 6f 6c 6c 65 63 74 6f 72 4f 70 65 6e 00 00 00 43 6f 6c 6c 65 63 74 6f 72 57 72 69 74 65 00 00 43 6f 6c 6c 65 63 74 6f 72 43 6c 6f 73 65 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=8
 
}
rule Spyware_Win32_WebHancer_A_3{
	meta:
		description = "Spyware:Win32/WebHancer.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0c 00 09 00 00 "
		
	strings :
		$a_01_0 = {77 65 62 68 61 6e 63 65 72 00 00 } //3
		$a_01_1 = {77 62 68 73 68 61 72 65 2e 64 6c 6c } //3 wbhshare.dll
		$a_01_2 = {77 65 62 68 64 6c 6c 2e 64 6c 6c } //3 webhdll.dll
		$a_00_3 = {57 65 62 48 61 6e 63 65 72 20 53 68 69 6d 20 77 69 6c 6c 20 6e 6f 74 20 66 75 6e 63 74 69 6f 6e } //3 WebHancer Shim will not function
		$a_01_4 = {57 68 49 6e 65 74 4d 75 74 65 78 } //3 WhInetMutex
		$a_01_5 = {57 48 43 55 52 54 3d 25 63 } //1 WHCURT=%c
		$a_01_6 = {57 48 41 56 47 54 3d 25 63 } //1 WHAVGT=%c
		$a_01_7 = {57 48 43 55 52 3d 25 30 34 64 } //1 WHCUR=%04d
		$a_00_8 = {5c 00 53 00 70 00 65 00 65 00 64 00 2e 00 6c 00 6f 00 67 00 } //1 \Speed.log
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_00_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_00_8  & 1)*1) >=12
 
}
rule Spyware_Win32_WebHancer_A_4{
	meta:
		description = "Spyware:Win32/WebHancer.A,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0f 00 09 00 00 "
		
	strings :
		$a_01_0 = {77 00 65 00 62 00 48 00 61 00 6e 00 63 00 65 00 72 00 20 00 5b 00 55 00 44 00 50 00 2f 00 49 00 50 00 5d 00 } //3 webHancer [UDP/IP]
		$a_01_1 = {77 00 65 00 62 00 48 00 61 00 6e 00 63 00 65 00 72 00 20 00 5b 00 54 00 43 00 50 00 2f 00 49 00 50 00 5d 00 } //3 webHancer [TCP/IP]
		$a_01_2 = {00 77 65 62 68 64 6c 6c 2e 64 6c 6c } //3 眀扥摨汬搮汬
		$a_01_3 = {72 65 67 77 65 62 68 2e 64 6c 6c } //3 regwebh.dll
		$a_01_4 = {52 65 67 57 68 57 73 32 4c 73 70 } //3 RegWhWs2Lsp
		$a_01_5 = {55 6e 72 65 67 57 68 57 73 32 4c 73 70 } //3 UnregWhWs2Lsp
		$a_01_6 = {77 68 41 67 65 6e 74 50 61 67 65 44 61 74 61 } //3 whAgentPageData
		$a_01_7 = {77 68 69 65 68 6c 70 72 2e 64 6c 6c } //3 whiehlpr.dll
		$a_01_8 = {70 72 6f 67 72 61 6d 73 5c 77 62 68 73 68 61 72 65 2e 64 6c 6c } //3 programs\wbhshare.dll
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3) >=15
 
}
rule Spyware_Win32_WebHancer_A_5{
	meta:
		description = "Spyware:Win32/WebHancer.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0d 00 09 00 00 "
		
	strings :
		$a_01_0 = {77 00 65 00 62 00 48 00 61 00 6e 00 63 00 65 00 72 00 } //3 webHancer
		$a_01_1 = {77 68 69 65 73 68 6d 2e 64 6c 6c } //3 whieshm.dll
		$a_01_2 = {23 21 24 5b 77 68 41 67 65 6e 74 5d 24 21 23 } //3 #!$[whAgent]$!#
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 77 65 62 48 61 6e 63 65 72 5c 43 43 } //3 Software\webHancer\CC
		$a_01_4 = {7b 32 33 35 37 31 45 36 43 2d 43 41 39 35 2d 34 61 61 36 2d 42 32 33 36 2d 36 44 42 32 42 32 36 42 42 36 38 43 7d } //3 {23571E6C-CA95-4aa6-B236-6DB2B26BB68C}
		$a_01_5 = {77 65 62 48 61 6e 63 65 72 20 43 75 73 74 6f 6d 65 72 20 43 6f 6d 70 61 6e 69 6f 6e 20 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 webHancer Customer Companion Information
		$a_01_6 = {43 4c 49 43 4b 41 57 41 59 } //1 CLICKAWAY
		$a_01_7 = {43 4c 49 43 4b 54 48 52 4f 55 47 48 } //1 CLICKTHROUGH
		$a_01_8 = {4e 4f 54 5f 41 42 41 4e 44 4f 4e 45 44 } //1 NOT_ABANDONED
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=13
 
}
rule Spyware_Win32_WebHancer_A_6{
	meta:
		description = "Spyware:Win32/WebHancer.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 77 61 72 65 5c 77 65 62 68 61 6e 63 65 72 } //2 software\webhancer
		$a_01_1 = {77 65 62 48 61 6e 63 65 72 20 53 75 72 76 65 79 20 43 6f 6d 70 61 6e 69 6f 6e } //2 webHancer Survey Companion
		$a_01_2 = {77 68 53 75 72 76 65 79 2e 69 6e 69 } //2 whSurvey.ini
		$a_01_3 = {36 41 44 31 30 46 31 38 2d 44 36 33 30 2d 34 65 62 36 2d 39 37 31 32 2d 34 37 30 33 37 31 45 39 35 46 35 37 } //1 6AD10F18-D630-4eb6-9712-470371E95F57
		$a_01_4 = {39 46 46 35 44 39 41 30 2d 35 45 45 42 2d 34 35 63 65 2d 42 35 30 30 2d 32 34 39 31 44 31 34 31 30 45 32 35 } //1 9FF5D9A0-5EEB-45ce-B500-2491D1410E25
		$a_01_5 = {37 31 42 41 37 32 35 30 2d 42 43 30 37 2d 34 63 64 32 2d 42 41 42 30 2d 33 45 38 34 46 45 42 42 31 30 38 45 } //1 71BA7250-BC07-4cd2-BAB0-3E84FEBB108E
		$a_01_6 = {42 38 34 45 37 33 31 42 2d 44 32 45 44 2d 34 65 38 32 2d 38 31 38 32 2d 41 35 32 46 44 34 37 31 34 32 38 34 } //1 B84E731B-D2ED-4e82-8182-A52FD4714284
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Spyware_Win32_WebHancer_A_7{
	meta:
		description = "Spyware:Win32/WebHancer.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {5c 50 72 6f 67 72 61 6d 73 5c 77 68 73 75 72 76 65 79 2e 65 78 65 } //3 \Programs\whsurvey.exe
		$a_01_1 = {5c 50 72 6f 67 72 61 6d 73 5c 77 68 61 67 65 6e 74 2e 65 78 65 } //3 \Programs\whagent.exe
		$a_01_2 = {5c 50 72 6f 67 72 61 6d 73 5c 77 65 62 68 64 6c 6c 2e 64 6c 6c } //3 \Programs\webhdll.dll
		$a_01_3 = {32 41 41 32 39 31 43 35 2d 30 33 45 37 2d 34 36 62 63 2d 41 43 38 43 2d 31 34 46 42 30 39 31 41 34 39 43 43 } //3 2AA291C5-03E7-46bc-AC8C-14FB091A49CC
		$a_01_4 = {43 75 73 74 6f 6d 65 72 20 43 6f 6d 70 61 6e 69 6f 6e } //1 Customer Companion
		$a_01_5 = {53 75 72 76 65 79 20 43 6f 6d 70 61 6e 69 6f 6e } //1 Survey Companion
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 77 65 62 48 61 6e 63 65 72 20 41 67 65 6e 74 } //1 Software\Microsoft\Windows\CurrentVersion\Uninstall\webHancer Agent
		$a_01_7 = {55 6e 72 65 67 57 68 57 73 32 4c 73 70 } //1 UnregWhWs2Lsp
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=11
 
}
rule Spyware_Win32_WebHancer_A_8{
	meta:
		description = "Spyware:Win32/WebHancer.A,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 77 65 62 48 61 6e 63 65 72 } //3 Software\webHancer
		$a_01_1 = {77 65 62 48 61 6e 63 65 72 20 49 6e 73 74 61 6c 6c 65 72 } //3 webHancer Installer
		$a_01_2 = {54 68 65 20 77 65 62 48 61 6e 63 65 72 20 62 61 73 65 20 64 69 72 65 63 74 6f 72 79 20 76 61 6c 75 65 20 69 73 20 6e 6f 74 20 73 65 74 } //3 The webHancer base directory value is not set
		$a_01_3 = {54 68 65 20 77 65 62 48 61 6e 63 65 72 20 27 25 73 27 20 72 65 67 69 73 74 72 79 20 76 61 6c 75 65 20 69 73 20 6e 6f 74 20 73 65 74 2e 20 20 54 68 65 20 73 6f 66 74 77 61 72 65 20 63 61 6e 6e 6f 74 20 62 65 20 72 65 6d 6f 76 65 64 2e } //3 The webHancer '%s' registry value is not set.  The software cannot be removed.
		$a_01_4 = {77 65 62 48 61 6e 63 65 72 20 73 6f 66 74 77 61 72 65 20 25 73 20 25 73 } //3 webHancer software %s %s
		$a_01_5 = {49 6e 69 74 69 61 6c 69 7a 61 74 69 6f 6e 20 6f 66 20 74 68 65 20 77 65 62 48 61 6e 63 65 72 20 69 6e 73 74 61 6c 6c 65 72 20 66 61 69 6c 65 64 2e } //3 Initialization of the webHancer installer failed.
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=15
 
}
rule Spyware_Win32_WebHancer_A_9{
	meta:
		description = "Spyware:Win32/WebHancer.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 09 00 0a 00 00 "
		
	strings :
		$a_01_0 = {57 00 68 00 49 00 6e 00 65 00 74 00 4d 00 75 00 74 00 65 00 78 00 } //2 WhInetMutex
		$a_01_1 = {77 00 65 00 62 00 48 00 61 00 6e 00 63 00 65 00 72 00 } //2 webHancer
		$a_01_2 = {6d 00 73 00 61 00 66 00 64 00 2e 00 64 00 6c 00 6c 00 } //2 msafd.dll
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 77 65 62 48 61 6e 63 65 72 } //2 Software\webHancer
		$a_01_4 = {77 65 62 68 64 6c 6c 2e 64 6c 6c } //2 webhdll.dll
		$a_01_5 = {73 70 6f 72 64 65 72 2e 64 6c 6c } //1 sporder.dll
		$a_01_6 = {36 41 38 30 33 39 33 34 2d 30 46 34 36 2d 34 38 39 61 2d 42 30 32 41 2d 38 41 36 44 44 46 45 33 30 42 42 30 2d } //1 6A803934-0F46-489a-B02A-8A6DDFE30BB0-
		$a_01_7 = {37 34 46 35 46 44 35 33 2d 33 36 38 46 2d 34 65 30 64 2d 38 30 35 42 2d 34 41 39 38 33 38 32 36 45 46 39 31 2d } //1 74F5FD53-368F-4e0d-805B-4A983826EF91-
		$a_01_8 = {39 31 32 42 34 44 36 34 2d 45 35 41 35 2d 34 62 66 63 2d 39 38 30 38 2d 34 43 46 31 34 39 46 32 46 39 36 35 2d } //1 912B4D64-E5A5-4bfc-9808-4CF149F2F965-
		$a_01_9 = {42 33 31 37 39 34 39 41 2d 45 45 32 45 2d 34 38 65 36 2d 42 45 34 31 2d 43 44 35 37 34 34 46 37 30 36 44 32 2d } //1 B317949A-EE2E-48e6-BE41-CD5744F706D2-
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=9
 
}