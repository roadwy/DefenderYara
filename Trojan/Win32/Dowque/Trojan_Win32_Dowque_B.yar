
rule Trojan_Win32_Dowque_B{
	meta:
		description = "Trojan:Win32/Dowque.B,SIGNATURE_TYPE_PEHSTR,14 00 0f 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {55 8b ec 81 c4 fc fe ff ff 53 33 d2 89 95 fc fe ff ff 8b d8 33 c0 55 68 2e 49 40 00 64 ff 30 64 89 20 68 ff 00 00 00 8d 85 00 ff ff ff 50 e8 69 fc ff ff 85 c0 75 07 c6 85 00 ff ff ff 43 8a 85 00 ff ff ff 50 e8 d2 fc ff ff 83 f8 01 1b c0 40 84 c0 75 07 c6 85 00 ff ff ff 43 8d 85 fc fe ff ff 8a 95 00 ff ff ff e8 40 f4 ff ff 8b 95 fc fe ff ff 8b c3 b9 43 49 40 00 e8 d2 f4 ff ff 33 c0 5a 59 59 64 89 10 68 35 49 40 00 8d 85 fc fe ff ff e8 f6 f2 ff ff c3 e9 64 ed ff ff eb ed 5b 8b e5 5d c3 } //02 00 
		$a_01_1 = {43 4c 53 49 44 5c 7b 32 41 33 45 43 46 31 44 2d 32 38 35 41 2d 34 36 33 45 2d 38 31 37 33 2d 37 44 30 35 32 43 38 46 41 32 37 30 7d } //02 00  CLSID\{2A3ECF1D-285A-463E-8173-7D052C8FA270}
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
		$a_01_3 = {6d 75 74 6f 75 65 78 65 6d 75 74 65 78 } //01 00  mutouexemutex
		$a_01_4 = {3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 } //01 00  :\Program Files\Outlook Express
		$a_01_5 = {6d 75 74 6f 75 44 4c 4c 6d 75 74 65 78 74 } //01 00  mutouDLLmutext
		$a_01_6 = {6d 75 74 6f 75 46 69 6c 65 4d 61 70 } //01 00  mutouFileMap
		$a_01_7 = {47 65 74 4d 73 67 48 6f 6f 6b 4f 6e } //01 00  GetMsgHookOn
		$a_01_8 = {64 65 6c 73 65 6c 66 2e 62 61 74 } //00 00  delself.bat
	condition:
		any of ($a_*)
 
}