
rule Trojan_Win32_MotePro{
	meta:
		description = "Trojan:Win32/MotePro,SIGNATURE_TYPE_PEHSTR_EXT,67 00 67 00 05 00 00 64 00 "
		
	strings :
		$a_02_0 = {50 72 6f 6d 6f 74 65 90 02 04 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 90 00 } //01 00 
		$a_01_1 = {46 78 53 74 61 74 75 73 45 78 5f 4c 61 75 6e 63 68 65 72 5f 45 76 65 6e 74 } //01 00  FxStatusEx_Launcher_Event
		$a_00_2 = {55 72 6c 4d 6b 47 65 74 53 65 73 73 69 6f 6e 4f 70 74 69 6f 6e } //01 00  UrlMkGetSessionOption
		$a_00_3 = {44 00 69 00 73 00 70 00 6c 00 61 00 79 00 20 00 49 00 6e 00 6c 00 69 00 6e 00 65 00 20 00 56 00 69 00 64 00 65 00 6f 00 73 00 } //01 00  Display Inline Videos
		$a_00_4 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 20 00 53 00 63 00 72 00 69 00 70 00 74 00 20 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 } //00 00  Disable Script Debugger
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_MotePro_2{
	meta:
		description = "Trojan:Win32/MotePro,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 63 6f 75 6e 74 2e 65 2d 6a 6f 6b 2e 63 6e 2f 63 6f 75 6e 74 2e 74 78 74 } //01 00  http://count.e-jok.cn/count.txt
		$a_01_1 = {53 6b 79 70 65 43 6c 69 65 6e 74 2e 65 78 65 } //03 00  SkypeClient.exe
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 65 2d 6a 6f 6b 2e 63 6e 2f 63 6f 75 6e 74 2f 75 70 64 61 74 65 64 61 74 61 2e 61 73 70 78 3f 69 64 3d } //03 00  http://www.e-jok.cn/count/updatedata.aspx?id=
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 65 2d 6a 6f 6b 2e 63 6e 2f 63 6e 66 67 2f 63 61 6e 76 69 65 77 2e 74 78 74 } //03 00  http://www.e-jok.cn/cnfg/canview.txt
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 65 2d 6a 6f 6b 2e 63 6e 2f 63 6e 66 67 2f 5f 70 6f 70 6c 6b 68 } //02 00  http://www.e-jok.cn/cnfg/_poplkh
		$a_01_5 = {3c 63 65 6e 74 65 72 3e 3c 69 66 72 61 6d 65 20 77 69 64 74 68 3d 25 64 20 68 65 69 67 68 74 3d 25 64 20 66 72 61 6d 65 62 6f 72 64 65 72 3d 30 20 53 43 52 4f 4c 4c 49 4e 47 3d 6e 6f 20 73 72 63 3d 22 25 73 22 3e 3c 2f 69 66 72 61 6d 65 3e 3c 2f 63 65 6e 74 65 72 3e } //00 00  <center><iframe width=%d height=%d frameborder=0 SCROLLING=no src="%s"></iframe></center>
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_MotePro_3{
	meta:
		description = "Trojan:Win32/MotePro,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 74 61 74 69 73 74 69 63 73 2e 74 6f 6d 2e 63 6f 6d 2f 73 63 72 69 70 74 73 2f 53 6b 79 70 65 2f 73 6f 62 61 72 2e 65 78 65 } //03 00  http://statistics.tom.com/scripts/Skype/sobar.exe
		$a_01_1 = {2e 74 6f 6d 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 70 72 6f 6d 6f 74 65 2f 70 72 6f 6d 6f 74 65 2e 64 6c 6c } //03 00  .tom.com/download/promote/promote.dll
		$a_01_2 = {2e 65 2d 6a 6f 6b 2e 63 6e 2f 63 6f 75 6e 74 } //02 00  .e-jok.cn/count
		$a_01_3 = {2f 75 70 64 61 74 65 64 61 74 61 2e 61 73 70 78 3f 69 64 3d } //02 00  /updatedata.aspx?id=
		$a_01_4 = {64 6f 77 6e 6e 6f 77 2e 74 78 74 } //01 00  downnow.txt
		$a_01_5 = {3c 63 65 6e 74 65 72 3e 3c 69 66 72 61 6d 65 20 77 69 64 74 68 3d 25 64 20 68 65 69 67 68 74 3d 25 64 20 66 72 61 6d 65 62 6f 72 64 65 72 3d 30 20 53 43 52 4f 4c 4c 49 4e 47 3d 6e 6f 20 73 72 63 3d 22 25 73 22 3e 3c 2f 69 66 72 61 6d 65 3e 3c 2f 63 65 6e 74 65 72 3e } //03 00  <center><iframe width=%d height=%d frameborder=0 SCROLLING=no src="%s"></iframe></center>
		$a_01_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 65 2d 6a 6f 6b 2e 63 6e 2f 63 6e 66 67 2f } //00 00  http://www.e-jok.cn/cnfg/
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_MotePro_4{
	meta:
		description = "Trojan:Win32/MotePro,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 69 63 74 69 6d 5f 4d 75 74 65 78 } //02 00  Victim_Mutex
		$a_01_1 = {26 76 65 72 3d 25 64 26 6d 61 63 3d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 } //03 00  &ver=%d&mac=%02X%02X%02X%02X%02X%02X
		$a_01_2 = {43 4c 53 49 44 20 3d 20 73 20 27 7b 30 46 41 32 34 45 33 45 2d 34 32 32 43 2d 34 44 39 34 2d 41 31 32 35 2d 31 30 34 46 33 32 33 35 32 43 39 30 7d 27 } //02 00  CLSID = s '{0FA24E3E-422C-4D94-A125-104F32352C90}'
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 79 79 69 73 6f 2e 63 6f 6d 2f 69 6e 74 65 72 6e 65 74 2f } //01 00  http://www.myyiso.com/internet/
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4e 65 77 20 57 69 6e 64 6f 77 73 5c 41 6c 6c 6f 77 } //01 00  Software\Microsoft\Internet Explorer\New Windows\Allow
		$a_01_5 = {50 00 72 00 6f 00 6d 00 6f 00 74 00 65 00 44 00 65 00 6d 00 6f 00 20 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 } //02 00  PromoteDemo Module
		$a_00_6 = {46 78 53 74 61 74 75 73 45 78 5f 4c 61 75 6e 63 68 65 72 5f 45 76 65 6e 74 00 00 00 54 45 4d 50 5f 4c 4f 41 44 5f 4c 49 42 52 41 52 59 5f 55 53 45 49 4e 47 00 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //02 00 
		$a_00_7 = {61 62 6f 75 74 3a 62 6c 61 6e 6b 00 00 00 00 42 75 74 74 6f 6e 50 6f 70 75 70 4b 69 6c 6c 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_MotePro_5{
	meta:
		description = "Trojan:Win32/MotePro,SIGNATURE_TYPE_PEHSTR,72 00 72 00 0c 00 00 03 00 "
		
	strings :
		$a_01_0 = {00 5c 5c 2e 5c 53 6d 61 72 74 76 73 64 00 00 00 00 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 00 25 30 32 58 } //64 00 
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 2f 70 72 6f 6d 6f 74 65 2f 70 72 6f 6d 6f 74 65 2e 64 6c 6c 00 5c 70 72 6f 6d 6f 74 65 2e 64 6c 6c 00 00 00 00 43 53 6b 79 70 65 49 6e 73 74 61 6c 6c 57 69 7a 61 72 64 00 43 54 72 61 79 49 63 6f 6e } //64 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 73 74 61 74 69 73 74 69 63 73 2e 74 6f 6d 2e 63 6f 6d 2f 73 63 72 69 70 74 73 2f 53 6b 79 70 65 2f 73 6f 62 61 72 2e 65 78 65 00 00 00 68 74 74 70 3a 2f 2f 36 31 2e 31 33 35 2e 31 35 39 2e 31 38 33 2f 69 6e 73 74 61 6c 6c 65 72 2f 73 6f 62 61 72 2e 65 78 65 00 00 00 68 74 74 70 3a 2f 2f 73 6b 79 70 65 2e 74 6f 6d 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 69 6e 73 74 61 6c 6c 2f 73 6f 62 61 72 2e 65 78 65 00 5c 73 6f 62 61 72 2e 65 78 65 } //03 00 
		$a_01_3 = {26 61 67 65 6e 74 69 64 3d 25 73 26 6f 70 3d 25 64 26 76 65 72 3d 25 64 26 6d 61 63 3d 25 73 } //01 00  &agentid=%s&op=%d&ver=%d&mac=%s
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_01_5 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetTickCount
		$a_01_6 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //01 00  CreateMutexA
		$a_01_7 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 41 } //01 00  GetTempFileNameA
		$a_01_8 = {54 72 61 63 6b 50 6f 70 75 70 4d 65 6e 75 } //01 00  TrackPopupMenu
		$a_01_9 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //01 00  OpenClipboard
		$a_01_10 = {53 68 65 6c 6c 5f 4e 6f 74 69 66 79 49 63 6f 6e 41 } //01 00  Shell_NotifyIconA
		$a_01_11 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}