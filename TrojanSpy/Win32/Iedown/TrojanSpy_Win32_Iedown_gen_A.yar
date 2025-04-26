
rule TrojanSpy_Win32_Iedown_gen_A{
	meta:
		description = "TrojanSpy:Win32/Iedown.gen!A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_2 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6f 6b 69 65 41 } //1 InternetGetCookieA
		$a_01_3 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //1 HttpSendRequestA
		$a_01_4 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 DllCanUnloadNow
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_01_6 = {26 50 4f 53 54 44 41 54 41 3d 4e 4f 57 26 } //1 &POSTDATA=NOW&
		$a_01_7 = {68 74 74 70 3a 2f 2f 32 30 33 2e 32 32 33 2e 31 35 39 2e 32 32 39 2f 7e 75 73 65 72 31 2f 65 72 72 6f 72 73 2f 64 62 33 2e 70 68 70 3f } //1 http://203.223.159.229/~user1/errors/db3.php?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}