
rule Trojan_Win32_Neoreblamy_BG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 10 00 00 "
		
	strings :
		$a_01_0 = {79 47 67 67 50 67 4e 54 72 6d 51 50 7a 4c 75 4d 58 7a 4b 49 70 67 6d 7a 77 74 5a 4c 74 56 59 74 49 4c } //1 yGggPgNTrmQPzLuMXzKIpgmzwtZLtVYtIL
		$a_01_1 = {73 52 64 45 52 67 6e 59 78 62 57 5a 63 50 6f 55 4b 69 69 4e 48 78 50 45 43 59 59 46 63 } //1 sRdERgnYxbWZcPoUKiiNHxPECYYFc
		$a_01_2 = {42 6d 6a 4b 48 73 66 6d 4e 4f 79 67 43 4e 50 4b 46 4a 56 6e 6f 6e 70 4d 77 53 79 52 70 45 6c 74 74 78 76 68 6e 47 48 51 49 } //1 BmjKHsfmNOygCNPKFJVnonpMwSyRpElttxvhnGHQI
		$a_01_3 = {4c 55 73 49 43 47 41 73 67 41 53 63 59 54 6d 6a 53 4a 52 41 70 4e 6d 6f 63 6d 4c 6b 73 5a 62 68 } //1 LUsICGAsgAScYTmjSJRApNmocmLksZbh
		$a_01_4 = {76 78 65 64 71 44 50 70 43 71 52 55 76 57 53 6b 52 4b 4e 74 4f 47 49 55 74 61 4f 43 51 6d 72 6a 47 7a } //1 vxedqDPpCqRUvWSkRKNtOGIUtaOCQmrjGz
		$a_01_5 = {75 45 6a 62 4d 47 64 6f 66 6a 47 44 76 7a 78 67 77 6a 76 56 66 64 53 54 74 76 47 5a 42 } //1 uEjbMGdofjGDvzxgwjvVfdSTtvGZB
		$a_01_6 = {77 42 57 4b 4b 47 4b 59 53 6e 47 76 77 58 53 51 51 47 45 67 69 4e 6b } //1 wBWKKGKYSnGvwXSQQGEgiNk
		$a_01_7 = {6d 77 76 44 4f 63 4f 55 54 58 72 66 62 4d 65 5a 43 42 78 58 75 4f 4a 44 42 63 4a 67 77 43 42 56 43 41 56 6d } //1 mwvDOcOUTXrfbMeZCBxXuOJDBcJgwCBVCAVm
		$a_01_8 = {65 44 49 70 4d 52 42 5a 65 59 6d 70 4e 52 50 64 63 62 4b 61 6f 63 46 6d 6d 74 6b 74 76 49 } //1 eDIpMRBZeYmpNRPdcbKaocFmmtktvI
		$a_01_9 = {4f 4b 78 52 68 71 70 62 52 4e 65 46 41 43 78 52 4f 77 79 79 70 67 4b 69 4e 55 56 4b 7a 7a 73 71 6b 67 } //1 OKxRhqpbRNeFACxROwyypgKiNUVKzzsqkg
		$a_01_10 = {41 56 69 53 52 53 49 76 47 46 73 79 50 78 4a 52 4f 6b 66 69 44 71 62 } //1 AViSRSIvGFsyPxJROkfiDqb
		$a_01_11 = {50 68 74 6f 45 79 7a 67 59 43 4a 48 50 51 44 6c 4c 66 6f 53 41 43 72 54 43 50 78 } //1 PhtoEyzgYCJHPQDlLfoSACrTCPx
		$a_01_12 = {6b 44 65 51 64 50 43 4b 56 51 74 58 44 6b 64 77 4a 63 48 6f 74 4a 42 4d 49 61 43 5a 7a 4d } //1 kDeQdPCKVQtXDkdwJcHotJBMIaCZzM
		$a_01_13 = {57 72 69 4e 66 48 48 4b 4c 4a 57 50 6d 6e 67 76 6d 68 51 65 56 6a 48 51 77 62 6f 73 } //1 WriNfHHKLJWPmngvmhQeVjHQwbos
		$a_01_14 = {41 71 70 4b 6d 4a 50 41 65 6f 54 4c 4d 4d 70 62 51 7a 77 4e 51 49 74 43 4f 47 7a 64 58 43 70 45 4e 50 } //1 AqpKmJPAeoTLMMpbQzwNQItCOGzdXCpENP
		$a_01_15 = {47 61 4d 6b 41 58 6c 42 41 70 75 50 50 58 6a 56 43 55 65 55 6d 65 62 7a 73 73 63 76 46 73 6d 62 6b 63 } //1 GaMkAXlBApuPPXjVCUeUmebzsscvFsmbkc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=4
 
}