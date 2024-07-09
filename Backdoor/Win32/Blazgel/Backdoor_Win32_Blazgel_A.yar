
rule Backdoor_Win32_Blazgel_A{
	meta:
		description = "Backdoor:Win32/Blazgel.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {b9 5a 36 c4 01 b8 e2 df 59 38 89 4c 24 3c 89 4c 24 34 89 4c 24 2c 8d 4c 24 28 89 44 24 38 89 44 24 30 89 44 24 28 8d 54 24 30 51 8d 44 24 3c 52 50 53 c7 44 24 3c c2 27 c5 01 ff 15 } //3
		$a_01_1 = {8d 14 92 d1 e2 48 75 f8 8b fd 83 c9 ff 33 c0 f2 ae b8 1f 85 eb 51 8b 7c 24 10 f7 ea f7 d1 49 c1 fa 05 0f be 0c 19 8b c2 83 e9 30 c1 e8 1f 03 d0 0f af ca 03 f9 4e 43 } //3
		$a_00_2 = {5c 64 65 6c 2e 62 61 74 } //1 \del.bat
		$a_00_3 = {5c 5c 2e 5c 75 73 62 6d 6f 75 73 65 62 } //1 \\.\usbmouseb
		$a_00_4 = {25 73 20 2d 72 20 22 25 73 } //1 %s -r "%s
		$a_00_5 = {4c 6f 61 64 52 6f 6f 74 4b 69 74 } //1 LoadRootKit
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule Backdoor_Win32_Blazgel_A_2{
	meta:
		description = "Backdoor:Win32/Blazgel.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {68 38 02 00 00 50 ?? ?? c7 84 24 ?? 02 00 00 88 88 88 88 c7 84 24 ?? 02 00 00 38 02 00 00 ff ?? 85 c0 } //5
		$a_00_1 = {42 4c 41 5a 49 4e 47 41 4e 47 45 4c 52 55 4e 4e 49 4e 47 } //2 BLAZINGANGELRUNNING
		$a_00_2 = {5c 5c 2e 5c 75 73 62 6d 6f 75 73 65 62 } //2 \\.\usbmouseb
		$a_00_3 = {56 49 50 2d 4e 56 28 32 30 30 } //1 VIP-NV(200
		$a_00_4 = {48 45 41 52 54 5f 42 45 41 54 20 25 73 20 25 64 } //1 HEART_BEAT %s %d
		$a_00_5 = {2b 4f 4b 20 4c 49 53 54 44 52 56 } //1 +OK LISTDRV
		$a_00_6 = {25 73 20 2d 6f 20 25 73 20 25 64 } //1 %s -o %s %d
		$a_00_7 = {55 53 45 52 49 44 3d 25 73 2c 43 41 50 3d 25 64 2c 4c 4f 47 49 4e 3d 25 73 2c 44 4f 43 4d 44 3d 25 64 2c 48 4f 53 54 4e 41 4d 45 3d 25 73 2c 4f 53 3d 25 73 } //1 USERID=%s,CAP=%d,LOGIN=%s,DOCMD=%d,HOSTNAME=%s,OS=%s
		$a_00_8 = {35 35 35 20 50 41 53 53 57 4f 52 44 3d 25 73 } //1 555 PASSWORD=%s
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=9
 
}