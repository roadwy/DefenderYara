
rule Trojan_Win32_Horst_C{
	meta:
		description = "Trojan:Win32/Horst.C,SIGNATURE_TYPE_PEHSTR_EXT,20 00 1d 00 0b 00 00 "
		
	strings :
		$a_00_0 = {5c 63 76 73 5c 76 63 70 72 6a 5c 53 50 72 6f 6a 5c 52 65 67 69 73 74 72 61 72 5c } //10 \cvs\vcprj\SProj\Registrar\
		$a_02_1 = {7b 25 4c 49 4e 4b 7d 90 05 04 01 00 3c 2f 53 55 42 4a 3e 90 05 04 01 00 3c 53 55 42 4a 90 05 04 01 00 42 4f 44 59 90 05 04 01 00 41 54 54 41 43 48 90 05 04 01 00 53 55 42 4a } //10
		$a_00_2 = {61 64 73 2e 7a 61 62 6c 65 6e 2e 63 6f 6d } //5 ads.zablen.com
		$a_00_3 = {32 31 36 2e 32 35 35 2e 31 37 38 2e 31 39 35 } //2 216.255.178.195
		$a_00_4 = {2f 6d 61 69 6c 2f 6d 61 69 6c 2e 61 73 70 78 3f } //2 /mail/mail.aspx?
		$a_00_5 = {25 73 5c 43 6f 6f 6b 69 65 73 } //2 %s\Cookies
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //1 Software\Microsoft\Internet Explorer\Main
		$a_00_7 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 4e 65 74 77 6f 72 6b } //1 \CurrentVersion\Policies\Network
		$a_00_8 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 } //1 \CurrentVersion\Policies\Explorer
		$a_01_9 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_01_10 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6f 6b 69 65 45 78 41 } //1 InternetGetCookieExA
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=29
 
}