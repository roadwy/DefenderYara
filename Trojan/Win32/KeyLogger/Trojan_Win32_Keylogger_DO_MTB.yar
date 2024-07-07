
rule Trojan_Win32_Keylogger_DO_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {2b c6 03 d9 50 8d 14 33 52 53 e8 b1 57 f5 ff 8b 5d 08 83 c4 0c 2b de 8b cd 57 53 e8 16 e2 f2 ff 84 c0 74 08 53 8b cd e8 e4 43 f4 ff 8b cd e8 88 e2 f2 ff 5f 8b c5 5e 5d 5b 59 c2 04 00 3b df 76 4c 3b d8 75 } //2
		$a_01_1 = {73 36 6a 01 8b cd e8 8b e2 f2 ff 8b 46 04 3b c7 75 05 b8 30 19 50 00 89 45 04 8b 4e 08 89 4d 08 8b 56 0c 89 55 0c 8a 48 ff fe c1 5f 88 48 ff 8b c5 5e 5d 5b 59 c2 04 00 6a 01 53 8b cd e8 9f e1 f2 ff 84 c0 74 29 } //2
		$a_01_2 = {3f 64 69 73 70 61 74 63 68 4d 61 70 40 43 48 74 6d 6c 53 6b 69 6e 44 6c 67 40 40 31 55 41 46 58 5f 44 49 53 50 4d 41 50 40 40 42 } //1 ?dispatchMap@CHtmlSkinDlg@@1UAFX_DISPMAP@@B
		$a_01_3 = {3f 64 69 73 70 61 74 63 68 4d 61 70 40 43 53 6d 61 6c 6c 44 6f 77 6e 6c 6f 61 64 4d 61 6e 61 67 65 72 44 6c 67 40 40 31 55 41 46 58 5f 44 49 53 50 4d 41 50 40 40 42 } //1 ?dispatchMap@CSmallDownloadManagerDlg@@1UAFX_DISPMAP@@B
		$a_01_4 = {3f 6d 65 73 73 61 67 65 4d 61 70 40 43 53 6d 61 6c 6c 44 6f 77 6e 6c 6f 61 64 4d 61 6e 61 67 65 72 41 70 70 40 40 31 55 41 46 58 5f 4d 53 47 4d 41 50 40 40 42 } //1 ?messageMap@CSmallDownloadManagerApp@@1UAFX_MSGMAP@@B
		$a_01_5 = {5f 75 6e 69 6e 73 64 6d 2e 62 61 74 } //1 _uninsdm.bat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}