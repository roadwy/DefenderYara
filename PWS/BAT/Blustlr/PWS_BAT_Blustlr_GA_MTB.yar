
rule PWS_BAT_Blustlr_GA_MTB{
	meta:
		description = "PWS:BAT/Blustlr.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 11 00 0b 00 00 "
		
	strings :
		$a_80_0 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 32 2e 30 2e 35 30 37 32 37 5c 49 6e 73 74 61 6c 6c 55 74 69 6c 2e 65 78 65 } //\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe  10
		$a_80_1 = {43 72 79 70 74 6f 46 69 6c 65 47 72 61 62 62 65 72 } //CryptoFileGrabber  1
		$a_80_2 = {5c 45 74 68 65 72 65 75 6d 5c 6b 65 79 73 74 6f 72 65 } //\Ethereum\keystore  1
		$a_80_3 = {53 75 62 6a 65 63 74 } //Subject  1
		$a_80_4 = {41 74 74 61 63 68 } //Attach  1
		$a_80_5 = {40 54 49 54 4c 45 20 52 65 6d 6f 76 69 6e 67 } //@TITLE Removing  1
		$a_80_6 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 41 70 70 4c 61 75 6e 63 68 2e 65 78 65 } //\Microsoft.NET\Framework\v4.0.30319\AppLaunch.exe  1
		$a_80_7 = {48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce  1
		$a_80_8 = {5c 53 74 75 62 5c 50 72 6f 6a 65 63 74 31 2e 76 62 70 } //\Stub\Project1.vbp  1
		$a_80_9 = {47 65 74 4b 65 79 62 6f 61 72 64 44 61 74 61 } //GetKeyboardData  1
		$a_80_10 = {53 63 72 65 65 6e 43 61 70 74 75 72 65 } //ScreenCapture  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=17
 
}