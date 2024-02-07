
rule PWS_Win32_QQpass_DJ{
	meta:
		description = "PWS:Win32/QQpass.DJ,SIGNATURE_TYPE_PEHSTR_EXT,19 00 18 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 6e 73 74 61 6c 6c 00 53 4f 46 54 57 41 52 45 5c 54 65 6e 63 65 6e 74 5c 51 51 } //01 00 
		$a_00_1 = {20 2f 53 54 41 54 3a 00 20 50 57 44 48 41 53 48 3a 00 00 00 20 2f 53 54 41 52 54 20 51 51 55 49 4e 3a } //01 00 
		$a_00_2 = {5c 73 79 73 74 68 65 6f 6c 64 6d 73 67 2e 74 78 74 } //01 00  \systheoldmsg.txt
		$a_00_3 = {5c 73 79 73 67 75 69 2e 67 69 66 } //01 00  \sysgui.gif
		$a_00_4 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 68 74 74 70 73 3a 2f 2f 61 63 63 6f 75 6e 74 2e 71 71 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 61 75 74 68 5f 66 6f 72 67 65 74 } //0a 00  explorer.exe https://account.qq.com/cgi-bin/auth_forget
		$a_01_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //0a 00  SetWindowsHookExA
		$a_01_6 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //00 00  GetSystemDirectoryA
	condition:
		any of ($a_*)
 
}