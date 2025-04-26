
rule BrowserModifier_Win32_Heazycrome{
	meta:
		description = "BrowserModifier:Win32/Heazycrome,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 0a 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 4c 43 61 73 65 28 66 73 6f 2e 47 65 74 45 78 74 65 6e 73 69 6f 6e 4e 61 6d 65 28 66 69 6c 65 2e 50 61 74 68 29 29 20 3d 20 5c 22 6c 6e 6b 5c 22 } //20 If LCase(fso.GetExtensionName(file.Path)) = \"lnk\"
		$a_01_1 = {45 76 65 6e 74 46 69 6c 74 65 72 20 73 65 74 68 6f 6d 65 50 61 67 65 32 } //20 EventFilter sethomePage2
		$a_01_2 = {43 6f 6e 73 74 20 6c 69 6e 6b 43 68 72 6f 6d 65 20 3d 20 5c 22 68 74 74 70 3a 2f 2f 39 6f 30 67 6c 65 2e 63 6f 6d 2f 5c 22 } //1 Const linkChrome = \"http://9o0gle.com/\"
		$a_01_3 = {43 6f 6e 73 74 20 6c 69 6e 6b 20 3d 20 5c 22 68 74 74 70 3a 2f 2f 6e 61 76 73 6d 61 72 74 2e 69 6e 66 6f 5c 22 } //1 Const link = \"http://navsmart.info\"
		$a_01_4 = {43 6f 6e 73 74 20 6c 69 6e 6b 20 3d 20 5c 22 68 74 74 70 3a 2f 2f 77 77 77 2e 6e 61 76 73 6d 61 72 74 2e 69 6e 66 6f 2f 5c 22 } //1 Const link = \"http://www.navsmart.info/\"
		$a_01_5 = {43 6f 6e 73 74 20 6c 69 6e 6b 20 3d 20 5c 22 68 74 74 70 3a 2f 2f 79 65 61 62 65 73 74 73 2e 63 63 5c 22 } //1 Const link = \"http://yeabests.cc\"
		$a_01_6 = {43 6f 6e 73 74 20 6c 69 6e 6b 20 3d 20 5c 22 68 74 74 70 3a 2f 2f 6a 79 68 6a 79 79 2e 74 6f 70 5c 22 } //1 Const link = \"http://jyhjyy.top\"
		$a_01_7 = {43 6f 6e 73 74 20 6c 69 6e 6b 20 3d 20 5c 22 68 74 74 70 3a 2f 2f 6e 61 76 69 67 61 74 69 6f 6e 2e 69 77 61 74 63 68 61 76 69 2e 63 6f 6d 2f 5c 22 } //1 Const link = \"http://navigation.iwatchavi.com/\"
		$a_01_8 = {78 6d 6c 48 74 74 70 2e 6f 70 65 6e 20 5c 22 47 45 54 5c 22 2c 20 5c 22 68 74 74 70 3a 2f 2f 62 62 74 62 66 72 2e 70 77 2f 47 65 74 48 50 48 6f 73 74 } //1 xmlHttp.open \"GET\", \"http://bbtbfr.pw/GetHPHost
		$a_01_9 = {74 6d 70 2e 6d 6f 66 } //1 tmp.mof
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=41
 
}