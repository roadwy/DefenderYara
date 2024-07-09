
rule Backdoor_Win32_Agent_ADB{
	meta:
		description = "Backdoor:Win32/Agent.ADB,SIGNATURE_TYPE_PEHSTR_EXT,72 00 71 00 0f 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 53 56 43 48 30 53 54 2e 45 58 45 } //1 C:\WINDOWS\SYSTEM32\SVCH0ST.EXE
		$a_00_1 = {2e 68 74 6d 47 45 54 } //1 .htmGET
		$a_00_2 = {2e 61 73 70 47 45 54 } //1 .aspGET
		$a_00_3 = {2e 68 74 6d 6c 47 45 54 } //1 .htmlGET
		$a_00_4 = {57 69 6e 64 6f 77 73 20 46 69 72 65 77 61 6c 6c } //1 Windows Firewall
		$a_00_5 = {63 3a 5c 70 61 67 65 66 69 6c 65 2e 70 69 66 } //1 c:\pagefile.pif
		$a_00_6 = {57 69 6e 64 6f 77 73 39 38 } //1 Windows98
		$a_00_7 = {57 69 6e 64 6f 77 73 39 35 } //1 Windows95
		$a_00_8 = {57 69 6e 64 6f 77 73 4e 54 } //1 WindowsNT
		$a_00_9 = {57 69 6e 64 6f 77 73 32 30 30 30 } //1 Windows2000
		$a_00_10 = {57 69 6e 64 6f 77 73 58 50 } //1 WindowsXP
		$a_00_11 = {57 69 6e 64 6f 77 73 32 30 30 33 } //1 Windows2003
		$a_00_12 = {66 75 63 6b 77 65 62 } //1 fuckweb
		$a_00_13 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 77 77 77 2e 62 61 69 64 75 2e 63 6f 6d } //1 Referer: http://www.baidu.com
		$a_02_14 = {33 c0 53 56 57 8d 7c 24 0c f3 ab 8d 44 24 0c 68 00 01 00 00 50 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c9 ff 33 c0 8d 54 24 0c f2 ae f7 d1 2b f9 68 3f 00 0f 00 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 54 24 10 83 e1 03 50 f3 a4 bf ?? ?? ?? ?? 83 c9 ff f2 ae f7 d1 2b f9 50 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 83 e1 03 f3 a4 ff 15 ?? ?? ?? ?? 85 c0 } //100
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_02_14  & 1)*100) >=113
 
}