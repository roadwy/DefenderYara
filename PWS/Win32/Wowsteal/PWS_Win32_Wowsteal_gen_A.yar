
rule PWS_Win32_Wowsteal_gen_A{
	meta:
		description = "PWS:Win32/Wowsteal.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0c 00 72 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 3a 5c 77 33 6f 34 77 2e 74 78 74 } //02 00  c:\w3o4w.txt
		$a_00_1 = {59 75 6c 67 61 6e 67 5f 46 69 6c 65 5f 55 70 64 61 74 65 } //02 00  Yulgang_File_Update
		$a_00_2 = {47 61 6d 65 4d 75 6d 61 } //03 00  GameMuma
		$a_80_3 = {63 3a 5c 46 69 6e 64 45 72 72 4c 6f 6e 67 46 6f 72 47 61 6d 65 2e 74 78 74 } //c:\FindErrLongForGame.txt  02 00 
		$a_00_4 = {5e 00 6e 00 47 00 61 00 4d 00 59 00 57 00 34 00 77 00 58 00 42 00 48 00 6a 00 41 00 4b 00 } //02 00  ^nGaMYW4wXBHjAK
		$a_00_5 = {69 00 24 00 41 00 74 00 47 00 5e 00 78 00 5f 00 4a 00 72 00 43 00 } //02 00  i$AtG^x_JrC
		$a_80_6 = {69 66 79 6f 75 64 6f 74 68 61 74 61 67 61 69 6e 69 77 69 6c 6c 6b 69 63 6b 79 6f 75 72 61 73 73 } //ifyoudothatagainiwillkickyourass  01 00 
		$a_80_7 = {50 72 69 76 61 74 65 5f 57 6f 77 5f 44 61 74 61 } //Private_Wow_Data  02 00 
		$a_80_8 = {46 75 63 6b 53 68 61 6e 64 61 } //FuckShanda  03 00 
		$a_00_9 = {72 69 73 6e 69 66 64 73 61 66 39 68 66 64 73 61 6f 66 33 66 6d 64 6f 73 69 67 68 67 66 64 73 67 } //03 00  risnifdsaf9hfdsaof3fmdosighgfdsg
		$a_00_10 = {4d 69 63 72 6f 73 6f 66 74 20 53 6f 66 74 20 44 65 62 75 67 65 72 } //02 00  Microsoft Soft Debuger
		$a_80_11 = {5c 64 61 74 61 5c 77 6f 6f 6f 6c 2e 64 61 74 } //\data\woool.dat  01 00 
		$a_80_12 = {77 6f 6f 6f 6c 38 38 2e 64 61 74 } //woool88.dat  02 00 
		$a_80_13 = {2d 30 38 30 30 32 42 33 30 33 30 39 44 7d 5c 73 68 65 6c 6c 5c 4f 70 65 6e 48 6f 6d 65 50 61 67 65 5c } //-08002B30309D}\shell\OpenHomePage\  02 00 
		$a_80_14 = {45 58 50 31 30 52 45 52 2e 63 6f 6d } //EXP10RER.com  04 00 
		$a_00_15 = {a0 e7 ef f4 ef a0 f4 f2 f9 } //04 00 
		$a_00_16 = {d2 e1 f6 cd ef ee ae e5 f8 e5 } //02 00 
		$a_00_17 = {d9 e1 e8 ef ef } //02 00 
		$a_00_18 = {cc e9 ee e5 e1 e7 e5 } //03 00 
		$a_00_19 = {45 2d 43 68 69 6e 61 5f 57 6f 77 45 78 65 63 2d } //02 00  E-China_WowExec-
		$a_00_20 = {2e 00 77 00 6f 00 77 00 2e 00 51 00 4f 00 4d 00 58 00 5c 00 } //03 00  .wow.QOMX\
		$a_00_21 = {71 69 6e 67 6c 61 6e 7a 78 39 31 31 40 31 36 } //01 00  qinglanzx911@16
		$a_00_22 = {5c 73 76 63 68 71 73 2e 65 78 65 } //03 00  \svchqs.exe
		$a_00_23 = {69 62 6d 2d 78 70 2f 68 7a 2f 77 6f 77 32 2e 61 73 70 } //01 00  ibm-xp/hz/wow2.asp
		$a_00_24 = {5c 73 76 63 68 70 73 74 2e 65 78 65 } //03 00  \svchpst.exe
		$a_00_25 = {26 73 75 62 6a 65 63 74 3d 77 6f 77 70 61 73 73 } //01 00  &subject=wowpass
		$a_80_26 = {77 6f 6f 6f 6c } //woool  02 00 
		$a_80_27 = {4d 6f 6f 6e 48 6f 6f 6b } //MoonHook  01 00 
		$a_01_28 = {26 70 61 73 73 3d } //02 00  &pass=
		$a_01_29 = {26 62 65 69 7a 68 75 3d } //01 00  &beizhu=
		$a_01_30 = {26 70 63 6e 61 6d 65 3d } //02 00  &pcname=
		$a_01_31 = {43 68 65 63 6b 42 6f 78 48 61 63 6b 46 69 72 65 77 61 6c 6c } //02 00  CheckBoxHackFirewall
		$a_01_32 = {43 68 65 63 6b 42 6f 78 48 61 63 6b 48 59 4a 4c 54 } //01 00  CheckBoxHackHYJLT
		$a_01_33 = {53 65 6e 64 20 4f 4b 21 } //02 00  Send OK!
		$a_00_34 = {6e 75 6d 3d 31 32 33 34 35 36 37 26 70 61 73 73 3d 70 61 73 73 77 6f 72 64 } //01 00  num=1234567&pass=password
		$a_00_35 = {36 36 36 36 36 37 37 37 36 36 36 36 36 36 36 36 36 36 65 66 66 65 65 } //01 00  666667776666666666effee
		$a_00_36 = {69 66 20 65 78 69 73 74 20 22 } //01 00  if exist "
		$a_00_37 = {67 6f 74 6f 20 74 72 79 } //01 00  goto try
		$a_00_38 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 44 65 62 75 67 5c 31 44 35 34 42 44 35 42 43 32 30 36 2e 64 6c 6c } //01 00  C:\WINDOWS\Debug\1D54BD5BC206.dll
		$a_00_39 = {31 44 35 34 42 44 35 42 43 32 30 36 2e 65 78 65 } //01 00  1D54BD5BC206.exe
		$a_00_40 = {32 2e 62 61 74 00 00 00 ff ff ff ff 0f 00 00 00 6e 6e 6e 6b 6c 6c 6c 64 66 73 66 64 64 64 64 } //01 00 
		$a_80_41 = {2e 6c 6f 67 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //.logon.worldofwarcraft.com  01 00 
		$a_80_42 = {57 6f 72 6c 64 20 6f 66 20 57 61 72 63 72 61 66 74 } //World of Warcraft  01 00 
		$a_80_43 = {47 78 57 69 6e 64 6f 77 43 6c 61 73 73 44 33 64 } //GxWindowClassD3d  01 00 
		$a_80_44 = {72 65 61 6c 6d 6c 69 73 74 2e 77 74 66 } //realmlist.wtf  01 00 
		$a_80_45 = {77 6f 77 2e 65 78 65 } //wow.exe  03 00 
		$a_00_46 = {25 73 3f 4d 61 69 6c 42 6f 64 79 3d 25 73 } //01 00  %s?MailBody=%s
		$a_00_47 = {47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 } //01 00  GetKeyboardType
		$a_00_48 = {70 61 73 73 3a 25 73 } //01 00  pass:%s
		$a_00_49 = {45 48 4c 4f 20 25 73 } //01 00  EHLO %s
		$a_80_50 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //application/x-www-form-urlencoded  01 00 
		$a_00_51 = {47 61 6d 65 49 44 3d } //01 00  GameID=
		$a_80_52 = {26 50 61 73 73 57 6f 72 64 3d } //&PassWord=  03 00 
		$a_80_53 = {26 57 6f 77 73 65 72 76 65 72 3d } //&Wowserver=  01 00 
		$a_80_54 = {26 53 79 73 74 65 6d 4e 61 6d 65 3d } //&SystemName=  03 00 
		$a_80_55 = {2e 63 6f 6d 2e 63 6e 2f 75 70 64 2f 77 6f 77 } //.com.cn/upd/wow  03 00 
		$a_80_56 = {2e 63 6f 6d 2e 63 6e 2f 75 70 64 2f 78 79 71 75 70 64 61 74 65 2e 61 73 70 3f } //.com.cn/upd/xyqupdate.asp?  02 00 
		$a_80_57 = {2e 65 74 73 6f 66 74 2e 63 6f 6d 2e 63 6e 2f } //.etsoft.com.cn/  03 00 
		$a_00_58 = {63 6e 31 2e 67 72 75 6e 74 2e 77 6f 77 63 68 69 6e 61 2e 63 6f 6d } //03 00  cn1.grunt.wowchina.com
		$a_00_59 = {63 6e 32 2e 67 72 75 6e 74 2e 77 6f 77 63 68 69 6e 61 2e 63 6f 6d } //04 00  cn2.grunt.wowchina.com
		$a_00_60 = {47 00 65 00 74 00 48 00 6f 00 6f 00 6b 00 53 00 74 00 61 00 74 00 75 00 73 00 2e 00 61 00 73 00 70 00 3f 00 47 00 55 00 49 00 44 00 3d 00 } //02 00  GetHookStatus.asp?GUID=
		$a_00_61 = {26 57 69 6e 4e 61 6d 65 3d } //02 00  &WinName=
		$a_00_62 = {55 73 65 72 3a 25 73 7c 50 61 73 73 3a 25 73 } //02 00  User:%s|Pass:%s
		$a_00_63 = {4d 65 73 73 61 67 65 2d 49 64 3a 20 3c } //02 00  Message-Id: <
		$a_00_64 = {65 68 6c 6f 20 76 69 70 0d 0a } //01 00 
		$a_00_65 = {3c 76 69 70 40 6d 69 63 72 6f 73 6f 66 74 2e } //01 00  <vip@microsoft.
		$a_00_66 = {3b 20 66 69 6c 65 6e 61 6d 65 3d 22 63 3a 5c } //03 00  ; filename="c:\
		$a_00_67 = {58 2d 4d 61 69 6c 65 72 3a 20 3c 46 4f 58 4d 41 49 4c 20 } //03 00  X-Mailer: <FOXMAIL 
		$a_02_68 = {44 41 54 41 0d 0a 00 00 ff ff ff ff 90 01 01 00 00 00 46 72 6f 6d 3a 20 3c 90 00 } //02 00 
		$a_00_69 = {48 6f 6f 6b 50 72 6f 63 } //02 00  HookProc
		$a_00_70 = {49 6e 73 74 61 6c 6c 48 6f 6f 6b } //02 00  InstallHook
		$a_01_71 = {53 74 61 72 74 48 6f 6f 6b } //01 00  StartHook
		$a_00_72 = {53 74 6f 70 48 6f 6f 6b } //01 00  StopHook
		$a_00_73 = {55 6e 48 6f 6f 6b } //01 00  UnHook
		$a_00_74 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //01 00  GetAsyncKeyState
		$a_01_75 = {4a 75 6d 70 48 6f 6f 6b 4f 6e } //01 00  JumpHookOn
		$a_01_76 = {4a 75 6d 70 48 6f 6f 6b 4f 66 66 } //02 00  JumpHookOff
		$a_03_77 = {4a 75 24 6d 70 48 6f 6f 23 6b 4f 66 40 66 00 00 90 04 0c 06 30 2d 39 41 2d 5a 00 90 00 } //03 00 
		$a_01_78 = {57 53 58 49 48 55 44 53 } //03 00  WSXIHUDS
		$a_02_79 = {1c ff ff 8b d8 c6 44 24 04 00 68 00 01 00 00 8d 44 24 08 50 53 e8 90 01 02 ff ff c6 84 24 04 01 00 00 00 68 00 01 00 00 8d 84 24 08 01 00 00 50 53 90 00 } //03 00 
		$a_00_80 = {c6 06 b8 c6 46 05 ff c6 46 06 e0 c6 46 07 00 c6 07 b8 c6 47 05 ff c6 47 06 e0 c6 47 07 00 } //03 00 
		$a_02_81 = {41 00 33 d2 89 10 6a 00 8b 45 08 50 e8 90 01 01 fc fe ff 8b f8 57 a1 90 01 02 41 00 50 b8 90 01 02 41 00 50 6a 03 e8 90 01 01 fc fe ff 8b f0 a1 90 01 02 41 00 89 30 85 f6 76 02 b3 01 8b c3 90 00 } //02 00 
		$a_00_82 = {ff ff 25 00 ff 00 00 3d 00 0d 00 00 74 07 3d 00 04 00 00 75 02 b3 01 8b c3 90 55 } //05 00 
		$a_02_83 = {8b 7c 24 1c 56 68 48 01 00 00 6a 01 57 e8 90 01 02 00 00 56 e8 90 01 02 00 00 83 c4 20 33 c0 eb 06 8d 9b 00 00 00 00 fe 0c 38 40 3d 48 01 00 00 72 f5 5f b0 01 5e c3 53 8b 5c 24 0c 56 8b c3 57 90 00 } //03 00 
		$a_00_84 = {50 8d 3c cd 00 00 00 00 8b 4e 0c 8a 54 39 04 8b 4e 2c 6a 04 6a 01 53 51 88 54 24 2c ff d5 8b 46 2c 6a 00 6a 01 8d 54 24 20 52 53 50 ff 15 54 c1 } //04 00 
		$a_02_85 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 90 01 01 8d 45 f4 8b d3 e8 90 01 02 ff ff 8b 55 f4 8b c7 e8 90 01 02 ff ff ff 45 f8 4e 75 d9 90 00 } //02 00 
		$a_00_86 = {8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 } //02 00 
		$a_00_87 = {74 11 6a 00 6a 00 68 f5 00 00 00 53 e8 } //02 00 
		$a_02_88 = {33 d2 89 50 05 8b 03 8b 40 09 85 c0 74 06 50 e8 90 01 02 ff ff 8b 03 33 d2 89 50 09 8b 03 8b 40 01 85 c0 74 06 50 e8 8e 96 ff ff 8b 03 33 d2 89 50 90 00 } //01 00 
		$a_00_89 = {6a 00 68 00 00 00 80 6a 00 68 00 00 00 80 68 00 00 cf 00 68 } //01 00 
		$a_00_90 = {c7 44 24 10 33 7d 79 00 } //01 00 
		$a_00_91 = {50 68 00 01 00 00 6a 0d 53 } //02 00 
		$a_00_92 = {8b 54 24 18 8b f0 8b c2 83 c4 0c 8d 78 01 eb 03 8d 49 00 8a 08 40 84 c9 75 f9 56 2b c7 6a 01 50 } //fb ff 
		$a_00_93 = {42 31 41 47 5f 57 49 4e 44 4f 57 } //fe ff  B1AG_WINDOW
		$a_00_94 = {41 43 44 53 65 65 34 2e 65 78 65 } //fc ff  ACDSee4.exe
		$a_00_95 = {5c 53 6f 66 74 5c 44 6f 77 6e 6c 6f 61 64 } //9c ff  \Soft\Download
		$a_01_96 = {e3 ba dc b1 ae f4 f8 f4 00 } //9c ff 
		$a_01_97 = {8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 } //fb ff 
		$a_00_98 = {77 6f 77 73 68 65 6c 6c 2e 63 6f 6d } //fb ff  wowshell.com
		$a_00_99 = {57 6f 77 53 68 65 6c 6c 2e 69 6e 69 } //fd ff  WowShell.ini
		$a_00_100 = {77 6f 77 68 65 61 64 2e 63 6f 6d } //fd ff  wowhead.com
		$a_00_101 = {74 68 6f 74 74 62 6f 74 2e 63 6f 6d } //fd ff  thottbot.com
		$a_00_102 = {77 6f 77 68 65 61 64 20 63 6c 69 65 6e 74 } //fc ff  wowhead client
		$a_00_103 = {67 61 6d 61 6e 69 61 2e 63 6f 6d } //e2 ff  gamania.com
		$a_00_104 = {77 77 77 2e 77 6f 77 69 6e 73 69 64 65 2e 6e 65 74 } //e2 ff  www.wowinside.net
		$a_00_105 = {75 69 2e 74 68 65 39 2e 63 6f 6d } //e2 ff  ui.the9.com
		$a_00_106 = {54 69 74 6c 65 42 61 72 44 72 61 77 41 70 70 49 63 6f 6e } //e2 ff  TitleBarDrawAppIcon
		$a_00_107 = {6d 61 69 6e 42 72 6f 77 73 65 72 54 69 74 6c 65 43 68 61 6e 67 65 } //e2 ff  mainBrowserTitleChange
		$a_00_108 = {45 66 66 65 63 74 2e 53 68 61 64 6f 77 2e } //ec ff  Effect.Shadow.
		$a_80_109 = {2e 77 6f 77 63 68 69 6e 61 2e 63 6f 6d } //.wowchina.com  ec ff 
		$a_00_110 = {77 77 77 2e 74 68 65 39 2e 63 6f 6d } //ec ff  www.the9.com
		$a_00_111 = {63 63 6d 2e 67 6f 76 2e 63 6e } //6a ff  ccm.gov.cn
		$a_00_112 = {4f 6e 6c 79 20 72 65 67 69 73 74 65 72 65 64 20 76 65 72 73 69 6f 6e 20 6f 66 20 49 70 61 72 6d 6f 72 20 63 61 6e 20 63 6c 65 61 6e } //6a ff  Only registered version of Iparmor can clean
		$a_00_113 = {53 63 72 61 70 65 42 6f 78 20 69 73 20 61 63 63 65 73 73 69 6e 67 } //00 00  ScrapeBox is accessing
	condition:
		any of ($a_*)
 
}