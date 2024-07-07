
rule Trojan_Win32_TrickBotCrypt_MX_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {73 70 6c 74 5c 69 6e 69 74 5f 76 } //1 splt\init_v
		$a_81_1 = {53 53 54 65 73 74 53 65 74 74 73 } //1 SSTestSetts
		$a_81_2 = {53 53 54 65 73 74 2e 44 6f 63 75 6d 65 6e 74 } //1 SSTest.Document
		$a_81_3 = {43 53 53 54 65 73 74 44 6f 63 } //1 CSSTestDoc
		$a_81_4 = {52 65 63 65 6e 74 20 46 69 6c 65 20 4c 69 } //1 Recent File Li
		$a_81_5 = {43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 } //1 CryptImportKey
		$a_81_6 = {5c 53 68 65 6c 6c 4e 65 77 } //1 \ShellNew
		$a_81_7 = {5c 73 68 65 6c 6c 5c 70 72 69 6e 74 74 6f 5c } //1 \shell\printto\
		$a_81_8 = {63 6f 6d 6d 64 6c 67 5f 46 69 6c 65 4e 61 6d 65 4f 4b } //1 commdlg_FileNameOK
		$a_81_9 = {63 6f 6d 6d 64 6c 67 5f 4c 42 53 65 6c 43 68 61 6e 67 65 64 4e 6f 74 69 66 79 } //1 commdlg_LBSelChangedNotify
		$a_81_10 = {41 66 78 46 72 61 6d 65 4f 72 56 69 65 77 34 32 73 } //1 AfxFrameOrView42s
		$a_81_11 = {4c 64 72 41 63 63 65 73 73 52 65 73 6f 75 72 63 65 } //1 LdrAccessResource
		$a_81_12 = {43 53 74 61 74 75 73 42 61 72 } //1 CStatusBar
		$a_81_13 = {6d 73 63 74 6c 73 5f 73 74 61 74 75 73 62 61 72 33 32 } //1 msctls_statusbar32
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}