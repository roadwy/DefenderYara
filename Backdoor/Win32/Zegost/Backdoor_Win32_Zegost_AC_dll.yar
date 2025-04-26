
rule Backdoor_Win32_Zegost_AC_dll{
	meta:
		description = "Backdoor:Win32/Zegost.AC!dll,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc3 00 ffffffb9 00 0c 00 00 "
		
	strings :
		$a_01_0 = {44 49 59 54 43 50 46 6c 6f 6f 64 00 44 49 59 55 44 50 46 6c 6f 6f 64 00 3e 43 4c 49 43 4b 20 4f 50 45 4e 20 50 41 47 45 } //50 䥄呙偃汆潯d䥄啙偄汆潯d䌾䥌䭃传䕐⁎䅐䕇
		$a_01_1 = {4d 75 6c 74 69 54 43 50 46 6c 6f 6f 64 } //50 MultiTCPFlood
		$a_01_2 = {61 57 31 6e 4c 6a 55 78 4e 7a 63 34 4f 44 67 75 59 32 39 74 4f 6a 63 77 4e 6a 59 3d } //20 aW1nLjUxNzc4ODguY29tOjcwNjY=
		$a_01_3 = {61 6e 4d 75 4d 6a 41 78 4d 54 45 32 4f 43 35 6a 62 32 30 36 4e 7a 41 33 4e 77 3d 3d } //20 anMuMjAxMTE2OC5jb206NzA3Nw==
		$a_01_4 = {64 32 39 79 61 33 42 79 5a 58 4e 7a 4f 43 35 6a 62 32 30 36 4f 44 41 34 4d 41 3d 3d } //20 d29ya3ByZXNzOC5jb206ODA4MA==
		$a_01_5 = {63 32 56 75 5a 47 31 35 63 33 46 73 4c 6d 4e 76 62 54 6f 34 4d 44 67 77 } //20 c2VuZG15c3FsLmNvbTo4MDgw
		$a_01_6 = {51 58 42 77 62 47 6c 6a 59 58 52 70 62 32 35 7a 58 46 78 57 54 58 64 68 63 6d 56 49 62 33 4e 30 54 33 42 6c 62 69 35 6c 65 47 55 3d } //10 QXBwbGljYXRpb25zXFxWTXdhcmVIb3N0T3Blbi5leGU=
		$a_01_7 = {51 33 4a 6c 59 58 52 6c 55 48 4a 76 59 32 56 7a 63 30 46 7a 56 58 4e 6c 63 6b 45 3d } //5 Q3JlYXRlUHJvY2Vzc0FzVXNlckE=
		$a_01_8 = {55 32 68 6c 62 47 78 46 65 47 56 6a 64 58 52 6c 51 51 3d 3d } //5 U2hlbGxFeGVjdXRlQQ==
		$a_01_9 = {55 32 56 30 55 32 56 6a 64 58 4a 70 64 48 6c 45 5a 58 4e 6a 63 6d 6c 77 64 47 39 79 52 47 46 6a 62 41 3d 3d } //5 U2V0U2VjdXJpdHlEZXNjcmlwdG9yRGFjbA==
		$a_01_10 = {55 6d 56 6e 61 58 4e 30 5a 58 4a 54 5a 58 4a 32 61 57 4e 6c 51 33 52 79 62 45 68 68 62 6d 52 73 5a 58 4a 42 } //5 UmVnaXN0ZXJTZXJ2aWNlQ3RybEhhbmRsZXJB
		$a_01_11 = {53 57 31 74 52 32 56 30 51 32 39 74 63 47 39 7a 61 58 52 70 62 32 35 54 64 48 4a 70 62 6d 64 42 } //5 SW1tR2V0Q29tcG9zaXRpb25TdHJpbmdB
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*50+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20+(#a_01_6  & 1)*10+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5+(#a_01_10  & 1)*5+(#a_01_11  & 1)*5) >=185
 
}