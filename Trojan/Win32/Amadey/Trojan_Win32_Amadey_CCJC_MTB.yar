
rule Trojan_Win32_Amadey_CCJC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.CCJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0a 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 6d 6f 7a 69 6c 6c 61 20 66 69 72 65 66 6f 78 } //1 program files\mozilla firefox
		$a_01_1 = {70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 6d 6f 7a 69 6c 6c 61 20 74 68 75 6e 64 65 72 62 69 72 64 } //1 program files\mozilla thunderbird
		$a_01_2 = {70 75 72 70 6c 65 5c 61 63 63 6f 75 6e 74 73 2e 78 6d 6c } //1 purple\accounts.xml
		$a_01_3 = {43 65 6e 74 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 CentBrowser\User Data\Default\Login Data
		$a_01_4 = {53 70 75 74 6e 69 6b 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 Sputnik\User Data\Default\Login Data
		$a_01_5 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 43 6f 6d 70 72 65 73 73 2d 41 72 63 68 69 76 65 20 2d 50 61 74 68 } //1 powershell -Command Compress-Archive -Path
		$a_01_6 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //2 encryptedUsername
		$a_01_7 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //2 encryptedPassword
		$a_01_8 = {46 69 6c 65 5a 69 6c 6c 61 5c 73 69 74 65 6d 61 6e 61 67 65 72 2e 78 6d 6c } //1 FileZilla\sitemanager.xml
		$a_01_9 = {4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 73 5c } //2 Monero\wallets\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*1+(#a_01_9  & 1)*2) >=13
 
}