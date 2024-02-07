
rule PWS_Win32_QQpass_DH{
	meta:
		description = "PWS:Win32/QQpass.DH,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2d 00 11 00 00 0a 00 "
		
	strings :
		$a_00_0 = {00 44 6f 77 6e 2e 64 6c 6c } //0a 00 
		$a_00_1 = {00 48 6f 6f 6b 43 6c } //0a 00 
		$a_00_2 = {00 48 6f 6f 6b 4f 6e } //02 00 
		$a_00_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 31 32 36 2e 63 6f 6d 2f } //02 00  http://www.126.com/
		$a_00_4 = {4e 61 6d 65 3d } //02 00  Name=
		$a_00_5 = {26 50 61 73 73 3d } //02 00  &Pass=
		$a_00_6 = {26 4d 61 63 3d } //01 00  &Mac=
		$a_01_7 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_00_8 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //01 00  UnhookWindowsHookEx
		$a_01_9 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_01_10 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_01_11 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //01 00  InternetOpenA
		$a_00_12 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //01 00  InternetConnectA
		$a_01_13 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 } //01 00  InternetCloseHandle
		$a_01_14 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //01 00  HttpSendRequestA
		$a_00_15 = {48 74 74 70 51 75 65 72 79 49 6e 66 6f 41 } //01 00  HttpQueryInfoA
		$a_00_16 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //00 00  HttpOpenRequestA
	condition:
		any of ($a_*)
 
}