
rule Trojan_Win32_HawkEyeReb_A_{
	meta:
		description = "Trojan:Win32/HawkEyeReb.A!!HawkEyeReb.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 0a 00 0c 00 00 "
		
	strings :
		$a_81_0 = {48 61 77 6b 45 79 65 20 52 65 62 6f 72 6e 58 } //1 HawkEye RebornX
		$a_81_1 = {5f 53 63 72 65 65 6e 73 68 6f 74 4c 6f 67 67 65 72 } //1 _ScreenshotLogger
		$a_81_2 = {5f 4b 65 79 53 74 72 6f 6b 65 4c 6f 67 67 65 72 } //1 _KeyStrokeLogger
		$a_81_3 = {57 65 62 63 61 6d } //1 Webcam
		$a_81_4 = {70 72 6f 63 65 73 73 68 61 63 6b 65 72 } //1 processhacker
		$a_81_5 = {70 72 6f 63 65 73 73 20 65 78 70 6c 6f 72 65 72 } //1 process explorer
		$a_81_6 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //1 \Google\Chrome\User Data
		$a_81_7 = {55 73 65 4f 70 65 72 61 50 61 73 73 77 6f 72 64 46 69 6c 65 } //1 UseOperaPasswordFile
		$a_81_8 = {4c 6f 61 64 50 61 73 73 77 6f 72 64 73 59 61 6e 64 65 78 } //1 LoadPasswordsYandex
		$a_81_9 = {55 73 65 46 69 72 65 66 6f 78 50 72 6f 66 69 6c 65 46 6f 6c 64 65 72 } //1 UseFirefoxProfileFolder
		$a_81_10 = {55 73 65 43 68 72 6f 6d 65 50 72 6f 66 69 6c 65 46 6f 6c 64 65 72 } //1 UseChromeProfileFolder
		$a_81_11 = {63 6f 6d 2e 61 70 70 6c 65 2e 57 65 62 4b 69 74 32 57 65 62 50 72 6f 63 65 73 73 } //1 com.apple.WebKit2WebProcess
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=10
 
}