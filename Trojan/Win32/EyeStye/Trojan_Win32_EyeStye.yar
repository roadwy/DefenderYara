
rule Trojan_Win32_EyeStye{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_02_0 = {ff 00 8d 85 90 09 46 00 ff 63 c6 85 90 01 03 ff 6f c6 85 90 01 03 ff 6e c6 85 90 01 03 ff 66 c6 85 90 01 03 ff 69 c6 85 90 01 03 ff 67 c6 85 90 01 03 ff 2e c6 85 90 01 03 ff 62 c6 85 90 01 03 ff 69 c6 85 90 01 03 ff 6e c6 85 90 00 } //3
		$a_00_1 = {55 8b ec 51 51 8b 45 08 66 81 38 4d 5a 74 04 33 c0 c9 c3 56 8b 70 3c 03 f0 81 3e 50 45 00 00 } //1
		$a_00_2 = {5f 5f 43 4c 45 41 4e 53 57 45 45 50 5f 5f } //2 __CLEANSWEEP__
		$a_00_3 = {63 6c 65 61 6e 73 77 65 65 70 2e 65 78 65 } //1 cleansweep.exe
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1) >=5
 
}
rule Trojan_Win32_EyeStye_2{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {5f 5f 43 4c 45 41 4e 53 57 45 45 50 5f 5f 00 } //1
		$a_03_1 = {8d 45 f4 50 68 9c 96 78 bf 6a 00 e8 90 02 15 ff 75 10 ff 75 0c ff 75 08 ff d0 90 00 } //2
		$a_00_2 = {80 7e 01 41 75 2f 80 7e 02 53 75 29 80 7e 03 53 75 23 } //2
		$a_03_3 = {c6 45 ec 25 c6 45 ed 73 c6 45 ee 5c c6 45 ef 25 c6 45 f0 73 88 5d 90 01 01 e8 90 00 } //2
		$a_03_4 = {c6 45 6c 25 c6 45 6d 73 c6 45 6e 5c c6 45 6f 25 c6 45 70 73 88 5d 90 01 01 e8 90 00 } //2
		$a_01_5 = {2a 44 72 6f 70 70 65 72 2a 21 6d 61 69 6e 20 3a 20 43 72 65 61 74 65 4d 75 74 65 78 2d 3e 45 52 52 4f 52 5f 41 4c 52 45 41 44 59 5f 45 58 49 53 54 53 00 } //-1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_00_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2+(#a_01_5  & 1)*-1) >=5
 
}
rule Trojan_Win32_EyeStye_3{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 35 30 20 4f 70 65 6e 69 6e 67 20 42 49 4e 41 52 59 20 6d 6f 64 65 20 64 61 74 61 20 63 6f 6e 6e 65 63 74 69 6f 6e } //1 150 Opening BINARY mode data connection
		$a_00_1 = {66 74 70 62 63 2e 64 6c 6c } //1 ftpbc.dll
		$a_00_2 = {2d 72 77 2d 72 2d 2d 72 2d 2d 20 31 20 30 20 30 20 } //1 -rw-r--r-- 1 0 0 
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_EyeStye_4{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 46 20 3b 20 25 73 20 3b 20 25 73 20 3b 20 25 73 } //1 FF ; %s ; %s ; %s
		$a_01_1 = {73 70 79 45 59 45 } //1 spyEYE
		$a_01_2 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 \Mozilla\Firefox\profiles.ini
		$a_01_3 = {54 61 6b 65 42 6f 74 47 75 69 64 } //1 TakeBotGuid
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_EyeStye_5{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {b8 07 63 f5 53 66 c7 44 24 90 01 01 bf b6 90 00 } //1
		$a_01_1 = {7f d5 c6 44 3e fe 0d c6 44 3e ff 0a c6 04 3e 00 } //1
		$a_01_2 = {2a 66 6f 72 75 6d 2a 6e 65 77 72 65 70 6c 79 2e 70 68 70 2a } //2 *forum*newreply.php*
		$a_01_3 = {73 70 79 53 70 72 65 61 64 2e 64 6c 6c 00 43 61 6c 6c } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=3
 
}
rule Trojan_Win32_EyeStye_6{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 61 6d 65 3d 22 73 65 63 6b 65 79 22 } //1 name="seckey"
		$a_03_1 = {3f 70 6c 5f 6e 61 6d 65 3d 90 02 08 26 75 69 64 3d 90 00 } //1
		$a_01_2 = {64 61 74 61 73 68 69 74 3d } //1 datashit=
		$a_02_3 = {8b f0 81 7d fc c8 00 00 00 76 90 01 01 8b 90 02 15 8b c6 e8 90 01 04 8b f8 8d 90 01 02 50 8b cf ba 50 00 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}
rule Trojan_Win32_EyeStye_7{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 6e 69 74 00 53 74 61 72 74 00 53 74 6f 70 } //1
		$a_01_1 = {54 61 6b 65 42 6f 74 47 75 69 64 } //1 TakeBotGuid
		$a_01_2 = {54 61 6b 65 47 61 74 65 54 6f 43 6f 6c 6c 65 63 74 6f 72 } //1 TakeGateToCollector
		$a_01_3 = {54 61 6b 65 47 65 74 50 61 67 65 } //1 TakeGetPage
		$a_01_4 = {62 6f 74 5f 67 75 69 64 } //1 bot_guid
		$a_01_5 = {43 61 6c 6c 62 61 63 6b 5f 4f 6e 42 65 66 6f 72 65 50 72 6f 63 65 73 73 55 72 6c } //1 Callback_OnBeforeProcessUrl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}
rule Trojan_Win32_EyeStye_8{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 61 6b 65 47 61 74 65 54 6f 43 6f 6c 6c 65 63 74 6f 72 33 } //1 TakeGateToCollector3
		$a_01_1 = {79 00 41 00 33 00 36 00 7a 00 41 00 34 00 38 00 64 00 45 00 68 00 66 00 72 00 76 00 67 00 68 00 47 00 52 00 67 00 35 00 37 00 68 00 35 00 55 00 6c 00 44 00 76 00 33 00 } //1 yA36zA48dEhfrvghGRg57h5UlDv3
		$a_01_2 = {73 6f 66 74 77 61 72 65 67 72 61 62 62 65 72 2e 64 6c 6c 00 49 6e 69 74 00 53 74 61 72 74 00 53 74 6f 70 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_EyeStye_9{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {67 75 69 64 3d 25 73 26 76 65 72 3d 25 75 26 69 65 3d 25 73 26 6f 73 3d 25 75 2e 25 75 2e 25 75 26 75 74 3d 25 73 26 63 63 72 63 3d 25 30 38 58 26 6d 64 35 3d 25 73 26 70 6c 67 3d 25 73 } //1 guid=%s&ver=%u&ie=%s&os=%u.%u.%u&ut=%s&ccrc=%08X&md5=%s&plg=%s
		$a_01_1 = {4d 61 69 6e 43 70 47 61 74 65 49 6e 70 75 74 } //1 MainCpGateInput
		$a_00_2 = {63 75 73 74 6f 6d 63 6f 6e 6e 65 63 74 6f 72 2e 64 6c 6c } //1 customconnector.dll
		$a_01_3 = {54 61 6b 65 42 6f 74 47 75 69 64 } //1 TakeBotGuid
		$a_01_4 = {25 73 26 73 74 61 74 3d 6f 6e 6c 69 6e 65 } //1 %s&stat=online
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule Trojan_Win32_EyeStye_10{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0c 00 00 "
		
	strings :
		$a_00_0 = {54 61 6b 65 42 6f 74 47 75 69 64 } //1 TakeBotGuid
		$a_00_1 = {54 61 6b 65 47 61 74 65 54 6f 43 6f 6c 6c 65 63 74 6f 72 } //1 TakeGateToCollector
		$a_00_2 = {8b 45 08 80 3c 01 3b 75 03 } //1
		$a_00_3 = {6a 11 6a 02 6a 02 e8 31 0e 00 00 89 84 b5 08 e5 ff ff 83 f8 ff 74 12 8d 8d 64 e3 ff ff 51 68 7e 66 04 80 50 } //1
		$a_00_4 = {72 61 69 66 66 65 69 73 65 6e 2e 72 75 2f 72 62 61 2f } //1 raiffeisen.ru/rba/
		$a_02_5 = {83 f8 23 0f 84 29 01 00 00 83 f8 3b 0f 84 20 01 00 00 6a 5b 57 e8 90 01 04 83 c4 08 90 00 } //1
		$a_00_6 = {8d 0c 02 8a 01 0f be f0 81 fe db 00 00 00 74 04 34 db 88 01 } //1
		$a_00_7 = {67 75 69 64 3d 25 73 26 76 65 72 3d 25 75 26 69 65 3d 25 73 26 6f 73 3d 25 75 2e 25 75 2e 25 75 26 75 74 3d 25 73 26 63 63 72 63 3d 25 30 38 58 26 6d 64 35 3d 25 73 26 70 6c 67 3d 25 73 26 77 61 6b 65 3d 25 75 } //1 guid=%s&ver=%u&ie=%s&os=%u.%u.%u&ut=%s&ccrc=%08X&md5=%s&plg=%s&wake=%u
		$a_00_8 = {6a 75 73 74 72 65 70 6c 61 63 65 3d } //1 justreplace=
		$a_00_9 = {65 6e 74 72 79 20 22 4a 61 62 62 65 72 4e 6f 74 69 66 69 65 72 22 } //1 entry "JabberNotifier"
		$a_00_10 = {53 70 79 45 79 65 5c 70 6c 75 67 69 6e 73 } //3 SpyEye\plugins
		$a_00_11 = {53 70 79 45 79 65 5f 53 74 61 72 74 } //3 SpyEye_Start
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*3+(#a_00_11  & 1)*3) >=4
 
}
rule Trojan_Win32_EyeStye_11{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 63 74 69 76 65 41 5a 2e 64 6c 6c 00 } //1
		$a_01_1 = {76 61 72 20 5f 61 61 7a 5f 72 65 7a 20 3d 20 31 3b } //1 var _aaz_rez = 1;
		$a_01_2 = {6a 00 6a 00 6a 03 6a 00 6a 00 68 bb 01 00 00 8d 4d c0 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_EyeStye_12{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 70 69 70 65 5c 70 72 65 73 70 25 64 } //1 \\.\pipe\presp%d
		$a_01_1 = {74 75 72 6e 20 6f 66 66 20 70 72 6f 61 63 74 69 76 65 5c 61 6e 74 69 76 69 72 75 73 2e } //1 turn off proactive\antivirus.
		$a_01_2 = {54 61 6b 65 42 6f 74 47 75 69 64 } //1 TakeBotGuid
		$a_01_3 = {52 64 70 47 65 74 4c 61 73 74 45 72 72 6f 72 } //1 RdpGetLastError
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule Trojan_Win32_EyeStye_13{
	meta:
		description = "Trojan:Win32/EyeStye,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 65 79 6c 6f 67 2e 64 6c 6c 00 } //1
		$a_01_1 = {73 6f 63 6b 73 2e 64 6c 6c 00 43 61 6c 6c 62 61 63 6b } //1
		$a_01_2 = {54 61 6b 65 42 6f 74 47 75 69 64 00 54 61 6b 65 47 61 74 65 } //1 慔敫潂䝴極d慔敫慇整
		$a_01_3 = {63 00 61 00 63 00 65 00 72 00 74 00 2e 00 70 00 65 00 6d 00 } //1 cacert.pem
		$a_01_4 = {67 72 61 62 6b 65 79 73 } //1 grabkeys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}