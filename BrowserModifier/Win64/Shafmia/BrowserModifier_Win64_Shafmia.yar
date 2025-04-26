
rule BrowserModifier_Win64_Shafmia{
	meta:
		description = "BrowserModifier:Win64/Shafmia,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 00 69 00 63 00 72 00 6f 00 41 00 70 00 70 00 5c 00 72 00 65 00 67 00 2e 00 62 00 61 00 74 00 } //1 MicroApp\reg.bat
		$a_01_1 = {65 00 64 00 67 00 65 00 2e 00 62 00 61 00 74 00 } //1 edge.bat
		$a_01_2 = {61 00 70 00 70 00 73 00 2d 00 68 00 65 00 6c 00 70 00 65 00 72 00 } //1 apps-helper
		$a_01_3 = {73 65 74 20 65 64 67 65 5f 65 78 74 } //1 set edge_ext
		$a_01_4 = {25 65 64 67 65 25 5c 45 78 74 65 6e 73 69 6f 6e 49 6e 73 74 61 6c 6c 46 6f 72 63 65 6c 69 73 74 22 20 2f 76 20 22 36 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 25 69 64 25 20 2f 66 } //1 %edge%\ExtensionInstallForcelist" /v "6" /t REG_SZ /d %id% /f
		$a_01_5 = {45 00 64 00 67 00 65 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 EdgeInstall.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
rule BrowserModifier_Win64_Shafmia_2{
	meta:
		description = "BrowserModifier:Win64/Shafmia,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 62 00 61 00 74 00 } //1 chrome.bat
		$a_01_1 = {61 00 70 00 70 00 73 00 2d 00 68 00 65 00 6c 00 70 00 65 00 72 00 } //1 apps-helper
		$a_01_2 = {73 65 74 20 63 68 72 6f 6d 65 5f 65 78 74 } //1 set chrome_ext
		$a_01_3 = {73 65 74 20 66 69 6c 65 3d 25 68 65 6c 70 65 72 25 5c 61 70 70 73 2e 63 72 78 } //1 set file=%helper%\apps.crx
		$a_01_4 = {25 63 68 72 6f 6d 65 25 5c 45 78 74 65 6e 73 69 6f 6e 49 6e 73 74 61 6c 6c 46 6f 72 63 65 6c 69 73 74 22 20 2f 76 20 22 36 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 25 69 64 25 20 2f 66 } //1 %chrome%\ExtensionInstallForcelist" /v "6" /t REG_SZ /d %id% /f
		$a_01_5 = {52 45 47 20 44 45 4c 45 54 45 20 25 62 61 73 65 33 32 25 5c 25 63 68 72 6f 6d 65 25 5c 45 78 74 65 6e 73 69 6f 6e 73 5c 25 69 64 25 20 2f 66 } //1 REG DELETE %base32%\%chrome%\Extensions\%id% /f
		$a_01_6 = {73 65 74 20 68 65 6c 70 65 72 3d 25 4c 6f 63 61 6c 41 70 70 64 61 74 61 25 5c 53 65 72 76 69 63 65 41 70 70 5c 61 70 70 73 2d 68 65 6c 70 65 72 } //1 set helper=%LocalAppdata%\ServiceApp\apps-helper
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}