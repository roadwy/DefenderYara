
rule PWS_Win32_Lmir_AAA{
	meta:
		description = "PWS:Win32/Lmir.AAA,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0b 00 00 0a 00 "
		
	strings :
		$a_00_0 = {65 6c 65 6d 65 6e 74 63 6c 69 65 6e 74 2e 65 78 65 } //01 00  elementclient.exe
		$a_00_1 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //01 00  UnhookWindowsHookEx
		$a_01_2 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_00_3 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00  CallNextHookEx
		$a_01_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //01 00  InternetOpenA
		$a_00_6 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //01 00  InternetConnectA
		$a_00_7 = {55 73 65 72 3d } //01 00  User=
		$a_00_8 = {50 61 73 73 3d } //01 00  Pass=
		$a_00_9 = {53 65 72 76 3d } //01 00  Serv=
		$a_00_10 = {50 65 6f 70 6c 65 3d } //00 00  People=
	condition:
		any of ($a_*)
 
}