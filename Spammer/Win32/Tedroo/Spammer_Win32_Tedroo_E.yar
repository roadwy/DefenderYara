
rule Spammer_Win32_Tedroo_E{
	meta:
		description = "Spammer:Win32/Tedroo.E,SIGNATURE_TYPE_PEHSTR,1d 01 1d 01 13 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 73 2f 25 73 2f 73 5f 65 73 74 72 2e 70 68 70 3f 69 64 3d 25 73 26 73 74 72 3d 37 30 35 2d 25 73 } //100 http://%s/%s/s_estr.php?id=%s&str=705-%s
		$a_01_1 = {68 74 74 70 3a 2f 2f 25 73 2f 25 73 2f 73 5f 72 65 70 6f 72 74 2e 70 68 70 3f 74 61 73 6b 3d 25 75 26 69 64 3d 25 73 } //100 http://%s/%s/s_report.php?task=%u&id=%s
		$a_01_2 = {6f 75 74 70 6f 73 74 2e 65 78 65 } //10 outpost.exe
		$a_01_3 = {5a 41 46 72 61 6d 65 57 6e 64 } //10 ZAFrameWnd
		$a_01_4 = {4d 50 43 53 56 43 2e 45 58 45 } //10 MPCSVC.EXE
		$a_01_5 = {24 46 52 4f 4d 5f 45 4d 41 49 4c } //10 $FROM_EMAIL
		$a_01_6 = {24 54 4f 5f 45 4d 41 49 4c } //10 $TO_EMAIL
		$a_01_7 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //10 InternetReadFile
		$a_01_8 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 WriteProcessMemory
		$a_01_9 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_01_10 = {4b 65 72 69 6f 50 65 72 73 6f 6e 61 6c 46 69 72 65 77 61 6c 6c 4d 61 69 6e 57 69 6e 64 6f 77 } //1 KerioPersonalFirewallMainWindow
		$a_01_11 = {4e 6f 72 74 6f 6e 20 50 65 72 73 6f 6e 61 6c 20 46 69 72 65 77 61 6c 6c } //1 Norton Personal Firewall
		$a_01_12 = {53 79 6d 61 6e 74 65 63 20 4e 41 4d 41 70 70 20 43 6c 61 73 73 } //1 Symantec NAMApp Class
		$a_01_13 = {4b 61 73 70 65 72 73 6b 79 20 41 6e 74 69 2d 48 61 63 6b 65 72 } //1 Kaspersky Anti-Hacker
		$a_01_14 = {4f 75 74 70 6f 73 74 20 46 69 72 65 77 61 6c 6c 20 50 72 6f } //1 Outpost Firewall Pro
		$a_01_15 = {79 61 68 6f 6f 2e 63 6f 6d } //1 yahoo.com
		$a_01_16 = {73 6d 74 70 2e 6d 61 69 6c 2e 72 75 } //1 smtp.mail.ru
		$a_01_17 = {73 6d 74 70 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //1 smtp.google.com
		$a_01_18 = {73 6d 74 70 2e 61 6f 6c 2e 63 6f 6d } //1 smtp.aol.com
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1) >=285
 
}