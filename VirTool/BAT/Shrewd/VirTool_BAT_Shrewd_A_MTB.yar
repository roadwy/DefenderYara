
rule VirTool_BAT_Shrewd_A_MTB{
	meta:
		description = "VirTool:BAT/Shrewd.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_81_0 = {75 73 65 72 43 68 72 6f 6d 69 75 6d 4c 6f 67 69 6e 44 61 74 61 50 61 74 68 } //1 userChromiumLoginDataPath
		$a_81_1 = {63 68 72 6f 6d 69 75 6d 42 61 73 65 50 61 74 68 } //1 chromiumBasePath
		$a_81_2 = {75 73 65 72 43 68 72 6f 6d 69 75 6d 43 6f 6f 6b 69 65 73 50 61 74 68 } //1 userChromiumCookiesPath
		$a_81_3 = {75 73 65 72 43 68 72 6f 6d 69 75 6d 42 6f 6f 6b 6d 61 72 6b 73 50 61 74 68 45 6e 64 } //1 userChromiumBookmarksPathEnd
		$a_81_4 = {75 73 65 72 43 68 72 6f 6d 69 75 6d 48 69 73 74 6f 72 79 50 61 74 68 } //1 userChromiumHistoryPath
		$a_81_5 = {43 68 72 6f 6d 69 75 6d 43 72 65 64 65 6e 74 69 61 6c 4d 61 6e 61 67 65 72 } //1 ChromiumCredentialManager
		$a_81_6 = {43 68 72 6f 6d 69 75 6d 55 74 69 6c 73 } //1 ChromiumUtils
		$a_81_7 = {44 50 41 50 49 43 68 72 6f 6d 65 41 6c 67 4b 65 79 46 72 6f 6d 52 61 77 } //1 DPAPIChromeAlgKeyFromRaw
		$a_81_8 = {44 50 41 50 49 43 68 72 6f 6d 69 75 6d 41 6c 67 46 72 6f 6d 4b 65 79 52 61 77 } //1 DPAPIChromiumAlgFromKeyRaw
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=8
 
}