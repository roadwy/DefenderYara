
rule TrojanDownloader_Win32_Dowritn_A{
	meta:
		description = "TrojanDownloader:Win32/Dowritn.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 6d 70 64 6f 77 6e 33 32 2e 64 6c 6c } //01 00  tmpdown32.dll
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 61 72 61 70 69 61 2e 63 6f 6d 2f 74 6d 70 2f 70 64 66 2e 70 64 66 } //01 00  http://www.larapia.com/tmp/pdf.pdf
		$a_00_2 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 3b 20 55 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 65 6e 3b 29 20 47 65 63 6b 6f 2f 33 30 30 36 30 33 30 39 20 46 69 72 65 66 6f 78 2f 31 2e 35 2e 30 2e 37 } //01 00  Mozilla/5.0 (Windows; U; Windows NT 5.1; en;) Gecko/30060309 Firefox/1.5.0.7
		$a_00_3 = {65 64 30 33 35 30 43 45 33 34 39 34 45 42 44 34 35 42 32 41 45 38 41 } //01 00  ed0350CE3494EBD45B2AE8A
		$a_00_4 = {53 79 73 74 65 6d 52 6f 6f 74 } //01 00  SystemRoot
		$a_00_5 = {73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  svchost.exe
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_7 = {57 69 6e 45 78 65 63 } //01 00  WinExec
		$a_02_8 = {64 ff 30 64 89 20 68 90 01 02 44 00 6a ff 6a 00 e8 90 01 02 fc ff 8b d8 85 db 74 0c e8 90 01 02 fc ff 3d b7 00 00 00 75 0d 53 e8 90 01 02 fc ff 33 c0 e8 90 01 02 fc ff 8d 55 ec b8 44 07 44 00 e8 90 01 02 fc ff 8b 55 ec b8 98 28 44 00 e8 90 01 02 fc ff 8d 45 e8 b9 58 07 44 00 8b 15 98 28 44 00 e8 90 01 02 fc ff 8b 45 e8 e8 90 01 02 fc ff 84 c0 0f 85 95 00 00 00 33 c0 55 68 90 01 02 44 00 64 ff 30 64 89 20 8d 45 e4 b9 90 01 02 44 00 8b 15 90 01 02 44 00 e8 90 01 02 fc ff 8b 55 e4 a1 90 01 02 44 00 e8 90 01 02 ff ff 6a 0a e8 90 01 02 fc ff 33 c0 5a 59 59 64 89 10 eb 0a 90 00 } //01 00 
		$a_02_9 = {33 c0 55 68 90 01 02 44 00 64 ff 30 64 89 20 6a 00 8d 45 e0 b9 90 01 02 44 00 8b 15 98 28 44 00 e8 90 01 02 fc ff 8b 45 e0 e8 90 01 02 fc ff 50 e8 90 01 02 fc ff 6a 0a e8 90 01 02 fc ff 33 c0 5a 59 59 64 89 10 eb 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}