
rule Trojan_Win32_WitchSyndrome_A_dha{
	meta:
		description = "Trojan:Win32/WitchSyndrome.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 14 00 00 "
		
	strings :
		$a_81_0 = {25 52 47 45 73 66 74 72 32 33 24 25 32 33 25 45 57 46 57 51 40 21 23 24 40 21 24 40 23 25 45 52 46 47 53 41 44 40 23 24 31 35 33 34 36 72 67 67 77 65 71 65 72 31 33 32 33 34 } //20 %RGEsftr23$%23%EWFWQ@!#$@!$@#%ERFGSAD@#$15346rggweqer13234
		$a_81_1 = {52 6a 38 6a 5a 56 77 46 56 41 3d 3d } //20 Rj8jZVwFVA==
		$a_81_2 = {55 6a 73 70 4b 42 51 4c 41 41 45 49 53 45 31 49 51 6c 5a 58 4e 6a 67 6f 4e 69 55 70 54 6b 31 6f 4a 56 64 42 4c 42 35 4d 4b 43 49 6a 4e 53 41 75 4b 69 46 58 51 55 77 55 62 32 67 59 4c 68 55 49 47 42 45 74 42 68 74 63 52 51 41 3d } //20 UjspKBQLAAEISE1IQlZXNjgoNiUpTk1oJVdBLB5MKCIjNSAuKiFXQUwUb2gYLhUIGBEtBhtcRQA=
		$a_81_3 = {63 6a 73 70 64 6b 45 35 4a 41 42 64 55 45 46 57 51 51 3d 3d } //20 cjspdkE5JABdUEFWQQ==
		$a_81_4 = {21 21 40 53 75 70 70 65 72 40 21 21 } //20 !!@Supper@!!
		$a_01_5 = {4c 73 44 6f 6d 61 69 6e 73 41 6e 64 50 43 73 } //20 LsDomainsAndPCs
		$a_01_6 = {53 45 43 55 52 49 54 59 5f 49 4d 50 45 52 53 4f 4e 41 54 49 4f 4e 5f 4c 45 56 45 4c } //4 SECURITY_IMPERSONATION_LEVEL
		$a_01_7 = {53 48 41 52 45 5f 49 4e 46 4f 5f 32 } //4 SHARE_INFO_2
		$a_01_8 = {57 54 53 5f 43 4f 4e 4e 45 43 54 53 54 41 54 45 5f 43 4c 41 53 53 } //4 WTS_CONNECTSTATE_CLASS
		$a_01_9 = {57 54 53 5f 53 45 53 53 49 4f 4e 5f 49 4e 46 4f } //4 WTS_SESSION_INFO
		$a_01_10 = {4c 4f 47 4f 4e 33 32 5f 50 52 4f 56 49 44 45 52 5f 44 45 46 41 55 4c 54 } //4 LOGON32_PROVIDER_DEFAULT
		$a_01_11 = {4c 4f 47 4f 4e 33 32 5f 4c 4f 47 4f 4e 5f 49 4e 54 45 52 41 43 54 49 56 45 } //4 LOGON32_LOGON_INTERACTIVE
		$a_01_12 = {57 54 53 47 65 74 41 63 74 69 76 65 43 6f 6e 73 6f 6c 65 53 65 73 73 69 6f 6e 49 64 } //4 WTSGetActiveConsoleSessionId
		$a_01_13 = {57 54 53 45 6e 75 6d 65 72 61 74 65 53 65 73 73 69 6f 6e 73 } //4 WTSEnumerateSessions
		$a_01_14 = {44 75 70 6c 69 63 61 74 65 54 6f 6b 65 6e 48 61 6e 64 6c 65 } //4 DuplicateTokenHandle
		$a_01_15 = {47 65 74 53 65 73 73 69 6f 6e 55 73 65 72 54 6f 6b 65 6e } //4 GetSessionUserToken
		$a_01_16 = {57 54 53 5f 43 55 52 52 45 4e 54 5f 53 45 52 56 45 52 5f 48 41 4e 44 4c 45 } //4 WTS_CURRENT_SERVER_HANDLE
		$a_01_17 = {45 78 65 63 77 6d 72 } //4 Execwmr
		$a_81_18 = {57 69 6e 4e 54 3a 2f 2f } //4 WinNT://
		$a_01_19 = {67 65 74 5f 41 6c 6c 4b 65 79 73 } //4 get_AllKeys
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*20+(#a_01_5  & 1)*20+(#a_01_6  & 1)*4+(#a_01_7  & 1)*4+(#a_01_8  & 1)*4+(#a_01_9  & 1)*4+(#a_01_10  & 1)*4+(#a_01_11  & 1)*4+(#a_01_12  & 1)*4+(#a_01_13  & 1)*4+(#a_01_14  & 1)*4+(#a_01_15  & 1)*4+(#a_01_16  & 1)*4+(#a_01_17  & 1)*4+(#a_81_18  & 1)*4+(#a_01_19  & 1)*4) >=60
 
}