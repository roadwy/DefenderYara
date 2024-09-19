
rule Trojan_Win32_Neoreblamy_ASO_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 14 00 00 "
		
	strings :
		$a_01_0 = {7a 50 4d 53 78 53 64 78 4d 68 51 59 52 7a 7a 44 47 54 59 48 47 43 58 65 69 56 42 7a 43 69 } //1 zPMSxSdxMhQYRzzDGTYHGCXeiVBzCi
		$a_01_1 = {72 57 7a 72 76 51 59 5a 57 57 62 6e 73 53 7a 55 41 6c 46 51 6a 65 4c 49 70 53 43 56 52 47 79 5a 6a 62 } //1 rWzrvQYZWWbnsSzUAlFQjeLIpSCVRGyZjb
		$a_01_2 = {5a 74 4d 67 6e 76 77 41 71 59 4a 45 78 4d 69 5a 46 6b 56 64 70 4d 53 73 4c 64 67 4b 71 4b 6a 62 58 70 } //1 ZtMgnvwAqYJExMiZFkVdpMSsLdgKqKjbXp
		$a_01_3 = {41 55 78 41 62 79 6f 50 4d 64 4e 64 61 4b 5a 5a 41 56 69 76 76 5a 41 54 6b 43 54 78 76 79 4a 64 72 5a 53 71 44 68 6e 75 4d 6e } //1 AUxAbyoPMdNdaKZZAVivvZATkCTxvyJdrZSqDhnuMn
		$a_01_4 = {57 65 43 4c 78 51 7a 6f 78 47 5a 48 5a 47 56 4e 4d 6e 63 72 42 57 41 65 4b 76 6e 6a 4e 4d } //1 WeCLxQzoxGZHZGVNMncrBWAeKvnjNM
		$a_01_5 = {77 41 4e 70 77 46 76 71 42 4c 64 51 62 48 5a 6b 4f 41 75 69 4c 6d 58 47 75 71 74 6e 76 74 6c 75 4c 43 } //1 wANpwFvqBLdQbHZkOAuiLmXGuqtnvtluLC
		$a_01_6 = {55 4f 72 69 77 4f 50 47 69 42 66 74 6c 52 6c 4b 6f 63 45 71 6a 46 72 48 61 75 41 61 4c 6c 79 52 52 58 45 68 } //1 UOriwOPGiBftlRlKocEqjFrHauAaLlyRRXEh
		$a_01_7 = {70 6e 49 49 50 4f 41 49 46 53 5a 53 64 4e 48 6b 55 72 65 74 44 43 71 4f 75 63 4d 56 4a 64 49 6d 43 73 43 6a 5a 4f 59 } //1 pnIIPOAIFSZSdNHkUretDCqOucMVJdImCsCjZOY
		$a_01_8 = {7a 43 55 72 64 70 79 69 4d 4e 6e 57 5a 51 50 6b 51 42 73 49 49 5a 6e 41 47 4a 6d 57 4c 45 } //1 zCUrdpyiMNnWZQPkQBsIIZnAGJmWLE
		$a_01_9 = {4d 4d 7a 6e 6a 49 63 53 4e 66 56 7a 6c 5a 49 4c 58 77 59 50 68 79 72 6b 64 50 52 4a 49 53 6f 47 55 5a } //1 MMznjIcSNfVzlZILXwYPhyrkdPRJISoGUZ
		$a_01_10 = {79 69 6a 57 6a 68 58 50 4f 5a 4a 46 64 70 5a 62 59 63 4a 45 63 42 4d 53 45 62 71 6d 72 62 55 4b 4b 77 48 69 71 56 5a 7a 67 75 } //1 yijWjhXPOZJFdpZbYcJEcBMSEbqmrbUKKwHiqVZzgu
		$a_01_11 = {65 69 65 67 49 61 4a 6a 69 51 45 4e 72 79 72 73 7a 77 73 67 43 6d 75 6a 71 52 7a 41 57 76 79 65 4d 76 56 } //1 eiegIaJjiQENryrszwsgCmujqRzAWvyeMvV
		$a_01_12 = {4e 4a 45 56 52 57 55 4f 4b 41 59 52 56 6d 4c 66 77 46 72 6d 73 75 4e 6d 47 79 69 49 } //1 NJEVRWUOKAYRVmLfwFrmsuNmGyiI
		$a_01_13 = {69 52 7a 54 45 59 44 45 47 44 6c 43 58 69 78 6f 56 52 4b 64 54 7a 68 51 65 71 76 78 58 53 50 77 78 62 } //1 iRzTEYDEGDlCXixoVRKdTzhQeqvxXSPwxb
		$a_01_14 = {6e 78 7a 41 71 78 42 41 79 64 57 6a 57 41 58 4e 6c 44 68 56 70 7a 58 56 50 45 63 51 44 4a 74 70 6a 69 75 64 74 75 51 7a 74 4c } //1 nxzAqxBAydWjWAXNlDhVpzXVPEcQDJtpjiudtuQztL
		$a_01_15 = {56 74 58 73 73 63 4a 72 4c 66 73 42 4a 75 6f 68 4c 74 41 4b 65 45 56 79 55 67 6a 47 70 64 49 41 67 44 } //1 VtXsscJrLfsBJuohLtAKeEVyUgjGpdIAgD
		$a_01_16 = {4f 5a 53 75 52 70 4a 76 4f 6c 69 61 6d 56 55 5a 71 78 4b 54 7a 59 44 57 6a 68 45 51 41 6d } //1 OZSuRpJvOliamVUZqxKTzYDWjhEQAm
		$a_01_17 = {47 4f 4f 4b 6a 69 50 77 45 71 70 78 66 73 77 79 49 47 6b 4f 64 61 4e 57 7a 4c 54 57 44 6f 4f 61 55 7a } //1 GOOKjiPwEqpxfswyIGkOdaNWzLTWDoOaUz
		$a_01_18 = {59 6f 75 65 44 42 6c 6c 41 45 51 5a 43 59 61 6e 72 65 70 51 6f 61 71 44 68 7a 46 74 74 49 6f 4e 53 47 4c 48 71 } //1 YoueDBllAEQZCYanrepQoaqDhzFttIoNSGLHq
		$a_01_19 = {62 45 53 47 6b 47 71 6c 52 51 4d 53 54 6b 71 48 4e 57 4c 55 46 74 73 5a 76 4e 4c 59 6c 44 5a 4a 50 55 7a 49 5a 67 67 } //1 bESGkGqlRQMSTkqHNWLUFtsZvNLYlDZJPUzIZgg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1) >=4
 
}