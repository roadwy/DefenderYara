
rule Trojan_Win32_QbotPws_A_{
	meta:
		description = "Trojan:Win32/QbotPws.A!!Qbot.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {52 69 70 53 61 76 65 64 50 61 73 73 65 73 28 29 3a 20 43 6f 49 6e 69 74 69 61 6c 69 7a 65 28 29 20 66 61 69 6c 65 64 } //1 RipSavedPasses(): CoInitialize() failed
		$a_81_1 = {52 69 70 53 61 76 65 64 50 61 73 73 65 73 28 29 3a 20 6c 6f 67 5f 70 72 6f 63 3d 4e 55 4c 4c } //1 RipSavedPasses(): log_proc=NULL
		$a_81_2 = {43 75 74 65 46 74 70 50 61 73 73 77 6f 72 64 73 28 29 3a 20 73 74 61 72 74 65 64 } //1 CuteFtpPasswords(): started
		$a_81_3 = {45 6e 75 6d 50 53 74 6f 72 61 67 65 28 29 3a 20 4f 75 74 6c 6f 6f 6b 20 61 63 63 3a 20 5b 25 73 5d 3d 5b 25 73 5d } //1 EnumPStorage(): Outlook acc: [%s]=[%s]
		$a_81_4 = {44 65 63 72 79 70 74 45 45 50 53 44 61 74 61 28 29 3a 20 43 72 79 70 74 55 6e 70 72 6f 74 65 63 74 44 61 74 61 28 29 20 66 61 69 6c 65 64 } //1 DecryptEEPSData(): CryptUnprotectData() failed
		$a_81_5 = {45 78 74 72 61 63 74 49 45 43 72 65 64 65 6e 74 69 61 6c 73 32 28 29 } //1 ExtractIECredentials2()
		$a_81_6 = {64 65 63 72 79 70 74 5f 66 69 72 65 66 6f 78 5f 6a 73 6f 6e 28 29 } //1 decrypt_firefox_json()
		$a_81_7 = {4f 75 74 6c 6f 6f 6b 44 65 63 72 79 70 74 50 61 73 73 77 6f 72 64 28 29 } //1 OutlookDecryptPassword()
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}