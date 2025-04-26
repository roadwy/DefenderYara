
rule Trojan_Win32_Neoreblamy_AST_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.AST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 14 00 00 "
		
	strings :
		$a_01_0 = {65 72 4f 67 56 42 42 53 77 52 77 56 76 70 53 64 72 6f 45 71 69 66 66 43 4a 45 45 77 52 70 52 6f 4d 52 } //1 erOgVBBSwRwVvpSdroEqiffCJEEwRpRoMR
		$a_01_1 = {53 76 77 50 4e 6e 47 64 76 48 4d 41 70 6e 73 54 65 4c 74 6a 4a 66 4e 79 4b 64 53 64 49 52 } //1 SvwPNnGdvHMApnsTeLtjJfNyKdSdIR
		$a_01_2 = {44 56 57 65 70 6e 56 4a 5a 48 49 46 69 68 47 4f 48 6e 6e 71 57 4c 51 50 42 47 70 6f 49 6f 59 51 6d 6c 52 4b 4a } //1 DVWepnVJZHIFihGOHnnqWLQPBGpoIoYQmlRKJ
		$a_01_3 = {77 66 6c 6e 6c 52 57 6a 55 5a 46 52 45 6c 78 43 41 62 5a 54 78 6b 79 62 71 66 73 72 43 6e 51 66 6f 70 4a 4b 67 70 64 7a 75 73 79 79 72 46 69 79 58 6f 4a } //1 wflnlRWjUZFRElxCAbZTxkybqfsrCnQfopJKgpdzusyyrFiyXoJ
		$a_01_4 = {63 79 65 63 5a 48 43 77 6a 44 78 58 73 46 7a 4f 4b 6d 65 45 4c 77 42 46 73 51 46 59 65 52 } //1 cyecZHCwjDxXsFzOKmeELwBFsQFYeR
		$a_01_5 = {78 59 57 61 44 65 53 79 43 4d 4b 4d 4c 52 58 73 68 50 75 6f 6c 4b 72 50 79 50 6b 65 52 67 47 66 6c 71 } //1 xYWaDeSyCMKMLRXshPuolKrPyPkeRgGflq
		$a_01_6 = {61 45 61 79 44 4a 62 7a 62 4c 76 7a 48 58 58 47 46 6b 65 45 70 46 67 47 42 63 46 6a 74 } //1 aEayDJbzbLvzHXXGFkeEpFgGBcFjt
		$a_01_7 = {63 56 77 4e 55 72 63 51 7a 75 4f 78 4e 66 6b 6d 58 56 62 49 55 67 66 43 42 76 65 42 61 69 6b 4d 51 45 72 73 57 70 44 73 75 } //1 cVwNUrcQzuOxNfkmXVbIUgfCBveBaikMQErsWpDsu
		$a_01_8 = {52 4f 6c 4c 53 76 53 6a 79 73 52 63 59 76 6a 58 4d 66 6c 72 4e 52 78 54 6b 41 71 64 45 5a } //1 ROlLSvSjysRcYvjXMflrNRxTkAqdEZ
		$a_01_9 = {7a 52 45 52 4e 45 5a 45 67 4f 66 51 45 61 50 78 4f 64 4f 76 6e 6b 4d 45 67 79 67 77 } //1 zRERNEZEgOfQEaPxOdOvnkMEgygw
		$a_01_10 = {6d 49 65 77 71 72 43 70 65 5a 4c 47 4d 57 66 4d 64 47 5a 61 55 74 78 4f 48 7a 59 49 } //1 mIewqrCpeZLGMWfMdGZaUtxOHzYI
		$a_01_11 = {54 41 78 63 68 41 77 68 58 63 6b 44 53 6f 76 64 6d 67 63 68 73 4f 57 5a 5a 44 64 62 71 } //1 TAxchAwhXckDSovdmgchsOWZZDdbq
		$a_01_12 = {6f 4d 52 4a 6c 55 43 51 44 62 48 4a 4b 43 51 65 75 6e 41 62 4f 77 6e 68 67 67 5a 70 } //1 oMRJlUCQDbHJKCQeunAbOwnhggZp
		$a_01_13 = {72 68 49 5a 46 55 72 4d 74 61 42 6c 53 79 64 79 59 6b 44 41 4e 54 59 6a 6d 52 7a 4e 65 61 41 6f 58 61 } //1 rhIZFUrMtaBlSydyYkDANTYjmRzNeaAoXa
		$a_01_14 = {45 75 59 52 49 72 4e 68 6a 69 56 46 56 7a 4a 54 62 4c 65 70 41 79 79 68 58 78 5a 6a 46 64 75 58 6d 6d 41 } //1 EuYRIrNhjiVFVzJTbLepAyyhXxZjFduXmmA
		$a_01_15 = {72 43 52 75 50 74 4b 75 4a 63 73 65 78 44 72 48 6b 72 45 64 4c 7a 62 4d 45 57 49 46 53 74 6c 71 41 4b 6e 52 61 67 45 41 41 } //1 rCRuPtKuJcsexDrHkrEdLzbMEWIFStlqAKnRagEAA
		$a_01_16 = {6a 65 79 41 72 42 66 4d 42 68 57 46 73 41 77 67 6b 53 62 71 43 74 6c 59 4c 55 5a 76 48 57 } //1 jeyArBfMBhWFsAwgkSbqCtlYLUZvHW
		$a_01_17 = {59 76 4a 62 4e 78 79 65 76 67 55 4c 41 65 4c 77 4d 56 45 58 71 63 6f 56 70 55 73 65 44 66 45 76 72 56 } //1 YvJbNxyevgULAeLwMVEXqcoVpUseDfEvrV
		$a_01_18 = {72 4d 67 64 5a 72 51 59 56 55 4b 6d 73 44 4e 5a 77 50 6a 46 79 56 78 6b 50 4e 41 57 42 } //1 rMgdZrQYVUKmsDNZwPjFyVxkPNAWB
		$a_01_19 = {74 4d 50 49 56 70 6f 65 70 4d 76 42 67 4a 68 4b 56 79 4d 71 6f 59 77 78 4c 7a 6c 42 70 67 47 71 64 69 79 43 67 } //1 tMPIVpoepMvBgJhKVyMqoYwxLzlBpgGqdiyCg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1) >=4
 
}