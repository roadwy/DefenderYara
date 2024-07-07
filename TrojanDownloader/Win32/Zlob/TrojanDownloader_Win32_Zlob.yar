
rule TrojanDownloader_Win32_Zlob{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR_EXT,ffffffa4 01 ffffffa4 01 09 00 00 "
		
	strings :
		$a_01_0 = {41 74 74 65 6e 74 69 6f 6e 21 } //100 Attention!
		$a_01_1 = {52 65 6d 6f 76 61 62 6c 65 } //100 Removable
		$a_00_2 = {72 65 62 6f 6f 74 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //100 reboot your computer
		$a_00_3 = {63 72 65 61 74 65 74 6f 6f 6c 68 65 6c 70 33 32 73 6e 61 70 73 68 6f 74 } //50 createtoolhelp32snapshot
		$a_01_4 = {64 65 6c 20 } //50 del 
		$a_01_5 = {4d 65 64 69 61 2d 43 6f 64 65 63 } //10 Media-Codec
		$a_00_6 = {2e 43 68 6c } //10 .Chl
		$a_00_7 = {76 69 64 65 6f } //10 video
		$a_00_8 = {53 4f 46 54 57 41 52 45 5c 47 52 45 41 54 49 53 5c 52 45 47 52 55 4e 32 5c } //-500 SOFTWARE\GREATIS\REGRUN2\
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*50+(#a_01_4  & 1)*50+(#a_01_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*-500) >=420
 
}
rule TrojanDownloader_Win32_Zlob_2{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 } //1
		$a_01_1 = {49 45 53 50 6c 75 67 69 6e } //1 IESPlugin
		$a_02_2 = {56 68 04 01 00 00 6a 00 be 90 01 04 56 e8 90 01 04 ff 74 24 14 e8 90 01 04 83 c4 10 48 78 1a 8b 4c 24 08 2b ce 8a 94 01 90 01 04 32 54 24 0c 48 88 90 90 90 01 04 79 ec 8b c6 5e c3 90 00 } //2
		$a_02_3 = {8a 08 40 84 c9 75 f9 2b c2 48 78 1c 8a 4c 24 90 01 01 81 90 01 05 8a 94 90 01 05 32 d1 48 88 90 90 90 01 04 79 ee 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=3
 
}
rule TrojanDownloader_Win32_Zlob_3{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {85 c0 75 14 68 2c 01 00 00 6a 08 ff 15 90 01 04 50 ff 15 90 01 04 56 8b 74 24 08 8a 16 84 d2 a3 90 01 04 8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2 c6 01 00 5e c3 90 00 } //1
		$a_01_1 = {46 69 6e 64 43 6c 6f 73 65 55 72 6c 43 61 63 68 65 00 00 00 46 69 6e 64 46 69 72 73 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 00 } //1
		$a_01_2 = {47 65 74 46 69 6c 65 56 65 72 73 69 6f 6e 49 6e 66 6f 41 00 47 65 74 46 69 6c 65 56 65 72 73 69 6f 6e 49 6e 66 6f 53 69 7a 65 41 00 } //1 敇䙴汩噥牥楳湯湉潦A敇䙴汩噥牥楳湯湉潦楓敺A
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Zlob_4{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR_EXT,63 02 63 02 0a 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //100 InternetOpenUrlA
		$a_00_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //100 ShellExecuteA
		$a_01_2 = {53 68 65 6c 6c 5f 4e 6f 74 69 66 79 49 63 6f 6e 41 } //100 Shell_NotifyIconA
		$a_00_3 = {44 69 73 70 6c 61 79 49 63 6f 6e } //100 DisplayIcon
		$a_01_4 = {6c 6f 61 64 00 } //100
		$a_01_5 = {61 6c 6c 65 72 74 00 } //100
		$a_02_6 = {61 6e 61 6c 90 02 0a 6d 6f 6e 73 74 65 72 73 2e 63 6f 6d 90 00 } //10
		$a_01_7 = {73 79 73 74 65 6d 20 6f 6e 20 63 6f 6d 70 75 74 65 72 20 69 73 20 64 61 6d 61 67 65 64 2e } //1 system on computer is damaged.
		$a_01_8 = {56 69 72 75 73 } //1 Virus
		$a_01_9 = {69 6e 66 65 63 74 65 64 } //1 infected
	condition:
		((#a_01_0  & 1)*100+(#a_00_1  & 1)*100+(#a_01_2  & 1)*100+(#a_00_3  & 1)*100+(#a_01_4  & 1)*100+(#a_01_5  & 1)*100+(#a_02_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=611
 
}
rule TrojanDownloader_Win32_Zlob_5{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR_EXT,63 02 63 02 0b 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //100 InternetOpenUrlA
		$a_00_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //100 ShellExecuteA
		$a_01_2 = {53 68 65 6c 6c 5f 4e 6f 74 69 66 79 49 63 6f 6e 41 } //100 Shell_NotifyIconA
		$a_00_3 = {44 69 73 70 6c 61 79 49 63 6f 6e } //100 DisplayIcon
		$a_01_4 = {6c 6f 61 64 00 } //100
		$a_01_5 = {61 6c 6c 65 72 74 00 } //100
		$a_01_6 = {74 6d 78 78 78 68 2e 64 6c 6c } //10 tmxxxh.dll
		$a_00_7 = {62 6c 6f 77 6a 6f 62 2e } //10 blowjob.
		$a_01_8 = {73 79 73 74 65 6d 20 6f 6e 20 63 6f 6d 70 75 74 65 72 20 69 73 20 64 61 6d 61 67 65 64 2e } //1 system on computer is damaged.
		$a_01_9 = {56 69 72 75 73 } //1 Virus
		$a_01_10 = {69 6e 66 65 63 74 65 64 } //1 infected
	condition:
		((#a_01_0  & 1)*100+(#a_00_1  & 1)*100+(#a_01_2  & 1)*100+(#a_00_3  & 1)*100+(#a_01_4  & 1)*100+(#a_01_5  & 1)*100+(#a_01_6  & 1)*10+(#a_00_7  & 1)*10+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=611
 
}
rule TrojanDownloader_Win32_Zlob_6{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 65 72 20 68 65 6c 70 65 72 20 6f 62 } //1 ser helper ob
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //1 Software\Microsoft\Internet Explorer\Main
		$a_00_2 = {53 74 61 72 74 20 50 61 67 65 } //1 Start Page
		$a_02_3 = {56 68 04 01 00 00 6a 00 be 90 01 04 56 e8 90 01 04 ff 74 24 14 e8 90 01 04 83 c4 10 48 78 1a 8b 4c 24 08 2b ce 8a 94 01 90 01 04 32 54 24 0c 48 88 90 90 90 01 04 79 ec 8b c6 5e c3 90 00 } //2
		$a_02_4 = {59 59 68 04 01 00 00 8d 44 24 14 50 6a ff 68 90 01 01 00 00 00 68 90 01 04 e8 90 01 04 59 59 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*2+(#a_02_4  & 1)*1) >=5
 
}
rule TrojanDownloader_Win32_Zlob_7{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR_EXT,ffffff97 00 ffffff97 00 08 00 00 "
		
	strings :
		$a_02_0 = {56 8b 74 24 08 a3 90 01 04 8a 16 84 d2 8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2 90 00 } //1
		$a_01_1 = {8b c8 b2 b4 2b d8 90 80 f2 c0 88 11 8a 54 0b 01 41 84 d2 75 f2 } //1
		$a_01_2 = {2e 70 68 70 3f 71 71 3d 25 73 } //10 .php?qq=%s
		$a_00_3 = {72 00 65 00 73 00 3a 00 2f 00 2f 00 25 00 73 00 } //10 res://%s
		$a_00_4 = {61 00 72 00 63 00 68 00 2e 00 6d 00 73 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 65 00 73 00 } //10 arch.msn.com/res
		$a_00_5 = {6c 00 6c 00 2f 00 68 00 74 00 74 00 70 00 5f 00 34 00 } //10 ll/http_4
		$a_00_6 = {2f 00 64 00 6e 00 73 00 65 00 } //10 /dnse
		$a_01_7 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 57 } //100 GetSystemDirectoryW
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_01_7  & 1)*100) >=151
 
}
rule TrojanDownloader_Win32_Zlob_8{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 08 00 00 "
		
	strings :
		$a_01_0 = {4d 00 79 00 42 00 47 00 54 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 5f 00 31 00 } //1 MyBGTransfer_1
		$a_01_1 = {5c 50 43 20 44 72 69 76 65 20 54 6f 6f 6c } //1 \PC Drive Tool
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 55 6c 74 69 6d 61 74 65 20 46 69 78 65 72 } //1 SOFTWARE\Ultimate Fixer
		$a_01_3 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 64 00 78 00 2e 00 64 00 6c 00 6c 00 } //1 C:\WINDOWS\sysdx.dll
		$a_01_4 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 6d 00 73 00 76 00 62 00 2e 00 64 00 6c 00 6c 00 } //1 C:\WINDOWS\msvb.dll
		$a_01_5 = {53 00 68 00 65 00 6c 00 6c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 44 00 65 00 6c 00 61 00 79 00 4c 00 6f 00 61 00 64 00 } //10 ShellServiceObjectDelayLoad
		$a_01_6 = {48 54 54 50 43 6c 69 65 6e 74 00 } //10
		$a_00_7 = {73 6f 66 74 77 61 72 65 5c 70 72 6f 64 75 63 74 73 } //10 software\products
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_00_7  & 1)*10) >=34
 
}
rule TrojanDownloader_Win32_Zlob_9{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8a 02 ffffff80 02 0d 00 00 "
		
	strings :
		$a_00_0 = {77 69 6e 65 78 65 63 } //100 winexec
		$a_00_1 = {77 72 69 74 65 66 69 6c 65 } //100 writefile
		$a_01_2 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //100 SeShutdownPrivilege
		$a_01_3 = {79 74 74 72 75 6f 76 } //100 yttruov
		$a_01_4 = {76 69 72 75 73 20 70 72 6f 74 65 63 74 69 6f 6e } //10 virus protection
		$a_01_5 = {61 6e 74 69 76 69 72 75 73 20 73 6f 66 74 77 61 72 65 } //10 antivirus software
		$a_01_6 = {61 6e 74 69 73 70 61 79 77 61 72 65 20 73 6f 66 74 77 61 72 65 } //20 antispayware software
		$a_01_7 = {6f 6e 20 79 6f 75 72 20 73 79 73 74 65 6d 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 2e } //20 on your system Windows Defender.
		$a_00_8 = {25 73 20 2f 64 65 6c 00 } //20 猥⼠敤l
		$a_00_9 = {25 73 20 2f 64 65 6c 32 00 } //10
		$a_02_10 = {2f 63 20 64 65 6c 90 02 05 25 73 90 02 05 3e 3e 90 02 05 6e 75 6c 6c 00 90 00 } //10
		$a_02_11 = {6a 00 6a 04 6a 02 6a 00 6a 01 68 00 00 00 40 68 90 01 02 40 00 e8 90 01 04 83 f8 ff 75 0c 90 00 } //100
		$a_00_12 = {80 3e 00 74 05 30 06 46 eb f6 c9 c2 08 00 } //100
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*20+(#a_01_7  & 1)*20+(#a_00_8  & 1)*20+(#a_00_9  & 1)*10+(#a_02_10  & 1)*10+(#a_02_11  & 1)*100+(#a_00_12  & 1)*100) >=640
 
}
rule TrojanDownloader_Win32_Zlob_10{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 07 00 00 "
		
	strings :
		$a_01_0 = {7b 34 31 46 36 31 37 30 44 2d 36 41 46 38 2d 34 31 38 38 2d 38 44 39 32 2d 39 44 44 41 42 33 43 37 31 41 37 38 7d } //1 {41F6170D-6AF8-4188-8D92-9DDAB3C71A78}
		$a_01_1 = {7b 32 33 45 44 32 32 30 36 2d 38 35 36 44 2d 34 36 31 41 2d 42 42 43 46 2d 31 43 32 34 36 36 41 43 35 41 45 33 7d } //1 {23ED2206-856D-461A-BBCF-1C2466AC5AE3}
		$a_01_2 = {53 54 41 52 54 45 52 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 } //10
		$a_00_3 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 74 6f 6f 6c 62 61 72 5c 77 65 62 62 72 6f 77 73 65 72 } //10 software\microsoft\internet explorer\toolbar\webbrowser
		$a_00_4 = {63 72 65 61 74 65 74 6f 6f 6c 68 65 6c 70 33 32 73 6e 61 70 73 68 6f 74 } //10 createtoolhelp32snapshot
		$a_00_5 = {70 72 6f 63 65 73 73 33 32 6e 65 78 74 } //10 process32next
		$a_00_6 = {68 00 74 00 74 00 70 00 } //5 http
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*5) >=46
 
}
rule TrojanDownloader_Win32_Zlob_11{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR_EXT,56 00 56 00 16 00 00 "
		
	strings :
		$a_01_0 = {e3 0e 3a 28 c1 2c ab 45 82 07 b1 d7 b6 9c 7f 83 } //1
		$a_01_1 = {cc 7b 8d 20 57 98 9e 4c 82 3b d0 4e 72 49 0a 67 } //1
		$a_01_2 = {13 cf 12 af 3b dc 1c 46 b5 ce 89 48 06 c1 53 03 } //1
		$a_01_3 = {4f 81 cf f4 0f 97 5d 40 a4 2c 0c e0 6e b9 73 73 } //1
		$a_01_4 = {a3 8a 41 88 f5 16 c2 4f a9 d8 90 b1 26 6d f8 41 } //1
		$a_01_5 = {c2 0c b7 3c 3f 30 6c 4a 82 4d 01 3a e8 cf db 6b } //1
		$a_01_6 = {fd 94 5a 69 d0 15 d7 4e 8f 40 d2 b3 bd c4 2c 15 } //1
		$a_01_7 = {07 51 d8 ac f9 9c 9e 4c b0 b7 39 94 0a 00 17 c0 } //1
		$a_01_8 = {3b b1 cb 31 4d 24 44 4c ae d5 dc ad 70 f6 62 81 } //1
		$a_01_9 = {a4 a4 8f 42 ec c8 7c 42 85 de 11 c8 0f 67 89 3a } //1
		$a_01_10 = {d1 04 bd ec 33 11 80 44 8a 8c bc 9f dd 54 d6 c1 } //1
		$a_01_11 = {16 bc dc 3a fa 19 59 4c 9c 22 e1 7c 71 b5 fd 7a } //1
		$a_01_12 = {bd db f4 c4 4c 4a 40 4b 97 da 2f e0 6d bb 29 01 } //1
		$a_01_13 = {08 2b 27 15 fe f6 71 4e b2 bd a5 9a d2 3e be 3c } //1
		$a_01_14 = {90 98 f7 05 a6 cf 53 4d 87 bc 2f 39 0d a6 64 5e } //1
		$a_01_15 = {02 4f c5 47 28 1b f1 45 ae 46 b5 cd fb 6e 79 26 } //1
		$a_01_16 = {50 7d 8b 21 37 bc a8 4f a5 7f 6e 8d e6 92 bd 79 } //1
		$a_01_17 = {42 68 6f 4e 65 77 2e 44 4c 4c } //50 BhoNew.DLL
		$a_01_18 = {45 6e 63 6f 64 65 50 6f 69 6e 74 65 72 } //10 EncodePointer
		$a_01_19 = {49 6e 74 65 72 6e 65 74 41 74 74 65 6d 70 74 43 6f 6e 6e 65 63 74 } //10 InternetAttemptConnect
		$a_01_20 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //10 IsDebuggerPresent
		$a_01_21 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //5 explorer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*50+(#a_01_18  & 1)*10+(#a_01_19  & 1)*10+(#a_01_20  & 1)*10+(#a_01_21  & 1)*5) >=86
 
}
rule TrojanDownloader_Win32_Zlob_12{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR_EXT,5b 00 5b 00 16 00 00 "
		
	strings :
		$a_01_0 = {e3 0e 3a 28 c1 2c ab 45 82 07 b1 d7 b6 9c 7f 83 } //1
		$a_01_1 = {cc 7b 8d 20 57 98 9e 4c 82 3b d0 4e 72 49 0a 67 } //1
		$a_01_2 = {13 cf 12 af 3b dc 1c 46 b5 ce 89 48 06 c1 53 03 } //1
		$a_01_3 = {4f 81 cf f4 0f 97 5d 40 a4 2c 0c e0 6e b9 73 73 } //1
		$a_01_4 = {a3 8a 41 88 f5 16 c2 4f a9 d8 90 b1 26 6d f8 41 } //1
		$a_01_5 = {c2 0c b7 3c 3f 30 6c 4a 82 4d 01 3a e8 cf db 6b } //1
		$a_01_6 = {fd 94 5a 69 d0 15 d7 4e 8f 40 d2 b3 bd c4 2c 15 } //1
		$a_01_7 = {07 51 d8 ac f9 9c 9e 4c b0 b7 39 94 0a 00 17 c0 } //1
		$a_01_8 = {3b b1 cb 31 4d 24 44 4c ae d5 dc ad 70 f6 62 81 } //1
		$a_01_9 = {a4 a4 8f 42 ec c8 7c 42 85 de 11 c8 0f 67 89 3a } //1
		$a_01_10 = {d1 04 bd ec 33 11 80 44 8a 8c bc 9f dd 54 d6 c1 } //1
		$a_01_11 = {16 bc dc 3a fa 19 59 4c 9c 22 e1 7c 71 b5 fd 7a } //1
		$a_01_12 = {bd db f4 c4 4c 4a 40 4b 97 da 2f e0 6d bb 29 01 } //1
		$a_01_13 = {08 2b 27 15 fe f6 71 4e b2 bd a5 9a d2 3e be 3c } //1
		$a_01_14 = {90 98 f7 05 a6 cf 53 4d 87 bc 2f 39 0d a6 64 5e } //1
		$a_01_15 = {02 4f c5 47 28 1b f1 45 ae 46 b5 cd fb 6e 79 26 } //1
		$a_01_16 = {50 7d 8b 21 37 bc a8 4f a5 7f 6e 8d e6 92 bd 79 } //1
		$a_01_17 = {42 68 6f 4e 65 77 2e 44 4c 4c } //50 BhoNew.DLL
		$a_01_18 = {73 00 65 00 61 00 72 00 63 00 68 00 2e 00 6d 00 73 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 64 00 6e 00 73 00 65 00 72 00 72 00 6f 00 72 00 2e 00 61 00 73 00 70 00 78 00 } //10 search.msn.com/dnserror.aspx
		$a_01_19 = {45 6e 63 6f 64 65 50 6f 69 6e 74 65 72 } //10 EncodePointer
		$a_01_20 = {49 6e 74 65 72 6e 65 74 41 74 74 65 6d 70 74 43 6f 6e 6e 65 63 74 } //10 InternetAttemptConnect
		$a_01_21 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //10 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*50+(#a_01_18  & 1)*10+(#a_01_19  & 1)*10+(#a_01_20  & 1)*10+(#a_01_21  & 1)*10) >=91
 
}
rule TrojanDownloader_Win32_Zlob_13{
	meta:
		description = "TrojanDownloader:Win32/Zlob,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 7a 31 2e 6e 66 2d 32 2e 6e 65 74 2f 35 31 32 2e 74 78 74 } //1 http://z1.nf-2.net/512.txt
		$a_01_1 = {25 73 5c 54 65 6d 70 5c 65 64 69 74 2e 6a 70 67 } //1 %s\Temp\edit.jpg
		$a_01_2 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 64 6c 6c 63 61 63 68 65 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 %SystemRoot%\System32\dllcache\explorer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}