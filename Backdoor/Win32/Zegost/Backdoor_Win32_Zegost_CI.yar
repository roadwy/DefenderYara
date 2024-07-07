
rule Backdoor_Win32_Zegost_CI{
	meta:
		description = "Backdoor:Win32/Zegost.CI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 32 26 25 73 20 22 25 73 22 } //1 cmd.exe /c ping 127.0.0.1 -n 2&%s "%s"
		$a_01_1 = {25 73 20 22 25 73 22 2c 43 72 65 61 74 65 46 6c 61 73 68 41 64 61 70 74 65 72 20 25 73 } //1 %s "%s",CreateFlashAdapter %s
		$a_01_2 = {20 25 2e 32 66 6d 73 2c 20 } //1  %.2fms, 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Backdoor_Win32_Zegost_CI_2{
	meta:
		description = "Backdoor:Win32/Zegost.CI,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {61 48 52 30 63 44 6f 76 4c 32 } //8 aHR0cDovL2
		$a_01_1 = {6c 74 5a 79 34 79 4d 44 45 78 4d 54 59 34 4c 6d 4e 76 62 53 39 30 5a 57 31 77 4c 32 6b 77 4c 6d 70 77 5a 77 3d 3d } //4 ltZy4yMDExMTY4LmNvbS90ZW1wL2kwLmpwZw==
		$a_01_2 = {70 7a 4c 6a 49 77 4d 54 45 78 4e 6a 67 75 59 32 39 74 4c 33 52 6c 62 58 41 76 61 6a 41 75 61 6e 4d 3d } //4 pzLjIwMTExNjguY29tL3RlbXAvajAuanM=
		$a_01_3 = {4a 58 4e 33 61 57 35 6b 62 33 64 7a 58 48 4e 35 63 33 52 6c 62 54 4d 79 58 48 4a 31 62 6d 52 73 62 44 4d 79 4c 6d 56 34 5a 51 3d 3d } //4 JXN3aW5kb3dzXHN5c3RlbTMyXHJ1bmRsbDMyLmV4ZQ==
		$a_01_4 = {56 31 52 54 52 32 56 30 51 57 4e 30 61 58 5a 6c 51 32 39 75 63 32 39 73 5a 56 4e 6c 63 33 4e 70 62 32 35 4a 5a 41 3d 3d } //2 V1RTR2V0QWN0aXZlQ29uc29sZVNlc3Npb25JZA==
		$a_01_5 = {56 31 52 54 55 58 56 6c 63 6e 6c 54 5a 58 4e 7a 61 57 39 75 53 57 35 6d 62 33 4a 74 59 58 52 70 62 32 35 42 } //2 V1RTUXVlcnlTZXNzaW9uSW5mb3JtYXRpb25B
		$a_01_6 = {64 32 6c 75 61 57 35 6c 64 43 35 6b 62 47 77 3d } //1 d2luaW5ldC5kbGw=
		$a_01_7 = {53 57 35 30 5a 58 4a 75 5a 58 52 53 5a 57 46 6b 52 6d 6c 73 5a 51 3d 3d } //1 SW50ZXJuZXRSZWFkRmlsZQ==
		$a_01_8 = {52 32 56 30 55 33 6c 7a 64 47 56 74 52 47 6c 79 5a 57 4e 30 62 33 4a 35 51 51 3d 3d } //1 R2V0U3lzdGVtRGlyZWN0b3J5QQ==
		$a_01_9 = {51 57 52 6b 51 57 4e 6a 5a 58 4e 7a 51 57 78 73 62 33 64 6c 5a 45 46 6a 5a 51 3d 3d } //1 QWRkQWNjZXNzQWxsb3dlZEFjZQ==
		$a_01_10 = {5a 32 56 30 61 47 39 7a 64 47 4a 35 62 6d 46 74 5a 51 3d 3d } //1 Z2V0aG9zdGJ5bmFtZQ==
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=15
 
}