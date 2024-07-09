
rule Trojan_Win32_Enfal_F{
	meta:
		description = "Trojan:Win32/Enfal.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 75 73 65 72 20 73 68 65 6c 6c 20 66 6f 6c 64 65 72 73 } //1 windows\currentversion\explorer\user shell folders
		$a_03_1 = {53 65 74 74 69 6e 67 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 53 74 61 72 74 5c [0-0a] 2e 65 78 65 } //1
		$a_03_2 = {2f 63 67 69 2d 62 69 6e 2f [0-06] 2e 63 67 69 00 } //1
		$a_02_3 = {56 8b 44 24 08 6a 0a 5e 03 c1 8a 96 ?? ?? ?? ?? 30 10 4e 79 ?? 41 3b 4c 24 0c 7c } //1
		$a_02_4 = {8d 45 fc 50 68 3f 00 0f 00 8d 86 ?? ?? ?? ?? 53 50 68 01 00 00 80 ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=4
 
}
rule Trojan_Win32_Enfal_F_2{
	meta:
		description = "Trojan:Win32/Enfal.F,SIGNATURE_TYPE_PEHSTR_EXT,47 00 3d 00 12 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //20 CreateRemoteThread
		$a_01_1 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //20 SeDebugPrivilege
		$a_00_2 = {8b 44 24 08 8b 4c 24 04 53 56 be 08 00 00 00 8a 11 8a 18 2a da 83 c1 04 88 18 8a 51 fd 8a 58 01 83 c0 02 2a da 4e 88 58 ff 75 e4 5e 5b c2 08 00 } //10
		$a_00_3 = {2f 68 74 74 70 64 6f 63 73 2f 6d 6d 2f } //10 /httpdocs/mm/
		$a_00_4 = {63 67 69 2d 62 69 6e 2f 43 6c 6e 70 70 35 2e 63 67 69 } //2 cgi-bin/Clnpp5.cgi
		$a_00_5 = {63 67 69 2d 62 69 6e 2f 52 77 70 71 31 2e 63 67 69 } //2 cgi-bin/Rwpq1.cgi
		$a_00_6 = {63 67 69 2d 62 69 6e 2f 4f 77 70 71 34 2e 63 67 69 } //2 cgi-bin/Owpq4.cgi
		$a_00_7 = {63 67 69 2d 62 69 6e 2f 44 77 70 71 33 2e 63 67 69 } //2 cgi-bin/Dwpq3.cgi
		$a_00_8 = {63 67 69 2d 62 69 6e 2f 43 72 70 71 32 2e 63 67 69 } //2 cgi-bin/Crpq2.cgi
		$a_00_9 = {2f 51 75 65 72 79 2e 74 78 74 } //2 /Query.txt
		$a_00_10 = {2f 43 63 6d 77 68 69 74 65 } //2 /Ccmwhite
		$a_00_11 = {2f 55 66 77 68 69 74 65 } //2 /Ufwhite
		$a_00_12 = {2f 44 66 77 68 69 74 65 } //2 /Dfwhite
		$a_00_13 = {2f 43 6d 77 68 69 74 65 } //2 /Cmwhite
		$a_00_14 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 6e 74 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 77 69 6e 6c 6f 67 6f 6e } //1 software\microsoft\windows nt\currentversion\winlogon
		$a_00_15 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //1 software\microsoft\windows\currentversion\run
		$a_00_16 = {65 78 65 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 exefile\shell\open\command
		$a_00_17 = {74 78 74 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 txtfile\shell\open\command
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*2+(#a_00_9  & 1)*2+(#a_00_10  & 1)*2+(#a_00_11  & 1)*2+(#a_00_12  & 1)*2+(#a_00_13  & 1)*2+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1) >=61
 
}