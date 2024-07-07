
rule TrojanProxy_Win32_Thrap_gen_A{
	meta:
		description = "TrojanProxy:Win32/Thrap.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,13 00 0c 00 08 00 00 "
		
	strings :
		$a_03_0 = {75 02 eb 38 c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 8b 4d 08 51 e8 90 01 02 00 00 83 c4 04 39 45 fc 7d 15 8b 55 08 03 55 fc 8a 02 32 45 0c 8b 4d 08 03 4d fc 88 01 eb d1 90 00 } //10
		$a_01_1 = {83 bd ec fd ff ff 0a 74 42 81 bd ec fd ff ff ac 00 00 00 75 12 83 bd e8 fd ff ff 0f 7e 09 83 bd e8 fd ff ff 20 7c 24 } //6
		$a_00_2 = {7e 66 73 6f 63 6b 31 2f 67 6f 64 2e 70 68 70 } //3 ~fsock1/god.php
		$a_01_3 = {4e 6c 4d 65 64 69 61 43 65 6e 74 65 72 } //3 NlMediaCenter
		$a_00_4 = {25 73 3f 70 69 70 3d 25 73 26 70 6f 72 74 3d 25 64 } //3 %s?pip=%s&port=%d
		$a_00_5 = {53 59 53 54 45 4d 5c 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 5c 53 65 72 76 69 63 65 73 5c 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 5c 50 61 72 61 6d 65 74 65 72 73 5c 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 5c 4c 69 73 74 } //1 SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List
		$a_00_6 = {47 25 79 25 6d 25 64 25 48 25 4d 25 53 2e 25 2e 20 25 70 20 25 45 20 25 55 20 25 43 3a 25 63 20 25 52 3a 25 72 20 25 4f 20 25 49 20 25 68 20 25 54 } //1 G%y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %h %T
		$a_00_7 = {44 6f 63 75 6d 65 6e 74 61 74 69 6f 6e 20 61 6e 64 20 73 6f 75 72 63 65 73 3a 20 68 74 74 70 3a 2f 2f 77 77 77 2e 73 65 63 75 72 69 74 79 2e 6e 6e 6f 76 2e 72 75 2f 73 6f 66 74 2f 33 70 72 6f 78 79 } //1 Documentation and sources: http://www.security.nnov.ru/soft/3proxy
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*6+(#a_00_2  & 1)*3+(#a_01_3  & 1)*3+(#a_00_4  & 1)*3+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=12
 
}