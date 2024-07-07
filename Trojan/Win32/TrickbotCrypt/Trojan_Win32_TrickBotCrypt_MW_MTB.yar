
rule Trojan_Win32_TrickBotCrypt_MW_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {4d 41 4c 53 45 52 56 49 43 45 } //1 MALSERVICE
		$a_81_1 = {52 65 63 65 6e 74 20 46 69 6c 65 20 4c 69 } //1 Recent File Li
		$a_81_2 = {5c 53 68 65 6c 6c 4e 65 77 } //1 \ShellNew
		$a_81_3 = {5c 73 68 65 6c 6c 5c 70 72 69 6e 74 74 6f 5c } //1 \shell\printto\
		$a_81_4 = {63 6f 6d 6d 64 6c 67 5f 46 69 6c 65 4e 61 6d 65 4f 4b } //1 commdlg_FileNameOK
		$a_81_5 = {63 6f 6d 6d 64 6c 67 5f 4c 42 53 65 6c 43 68 61 6e 67 65 64 4e 6f 74 69 66 79 } //1 commdlg_LBSelChangedNotify
		$a_81_6 = {41 66 78 46 72 61 6d 65 4f 72 56 69 65 77 34 32 73 } //1 AfxFrameOrView42s
		$a_81_7 = {43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 } //1 CryptImportKey
		$a_81_8 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //1 SizeofResource
		$a_81_9 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //1 FindResourceA
		$a_81_10 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}