
rule Trojan_Win32_Neoreblamy_ASJ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0f 00 00 "
		
	strings :
		$a_01_0 = {68 53 7a 41 43 65 73 41 77 70 62 62 75 65 42 58 66 55 71 56 47 62 4a } //1 hSzACesAwpbbueBXfUqVGbJ
		$a_01_1 = {59 66 57 65 4e 56 4e 48 66 66 73 71 4c 47 71 73 64 66 72 6a 4e 53 4d 64 59 4f 64 78 55 78 52 70 } //1 YfWeNVNHffsqLGqsdfrjNSMdYOdxUxRp
		$a_01_2 = {42 61 45 7a 73 51 4d 45 59 54 43 67 6d 48 78 59 4d 4a 52 63 50 4e 6f 77 77 65 } //1 BaEzsQMEYTCgmHxYMJRcPNowwe
		$a_01_3 = {79 56 72 43 61 64 59 69 6a 4c 56 70 71 68 61 73 54 5a 6e 78 64 6b 79 6d 47 59 4a 52 71 } //1 yVrCadYijLVpqhasTZnxdkymGYJRq
		$a_01_4 = {42 6b 42 64 66 66 75 53 78 48 62 76 4a 4a 54 6d 63 49 55 7a 67 67 72 6e 72 65 71 75 75 } //1 BkBdffuSxHbvJJTmcIUzggrnrequu
		$a_01_5 = {76 61 44 48 45 61 7a 4d 4a 4c 52 41 4d 72 4c 63 4c 74 67 73 55 53 64 6a 45 41 65 } //1 vaDHEazMJLRAMrLcLtgsUSdjEAe
		$a_01_6 = {78 70 77 58 44 70 47 4d 4c 73 57 59 58 4d 78 52 73 4e 59 46 43 71 79 } //1 xpwXDpGMLsWYXMxRsNYFCqy
		$a_01_7 = {52 77 49 61 74 67 70 51 4a 67 41 4b 58 72 47 70 63 46 7a 74 56 62 50 77 57 69 69 51 44 4e 4c 6e } //1 RwIatgpQJgAKXrGpcFztVbPwWiiQDNLn
		$a_01_8 = {71 71 4b 77 4d 4f 76 64 61 4c 54 68 77 73 47 4a 63 6c 6e 6c 51 6e 70 43 6f 70 44 50 77 66 41 4e 6c 66 4a 4c 47 53 6e } //1 qqKwMOvdaLThwsGJclnlQnpCopDPwfANlfJLGSn
		$a_01_9 = {45 6c 4e 42 41 44 51 72 77 72 71 49 43 74 64 4d 64 65 4f 6f 41 72 41 43 65 63 69 } //1 ElNBADQrwrqICtdMdeOoArACeci
		$a_01_10 = {6e 44 79 43 6d 55 7a 78 55 58 6b 58 65 43 75 67 5a 77 6d 6e 64 52 42 46 58 6f 4f 72 79 } //1 nDyCmUzxUXkXeCugZwmndRBFXoOry
		$a_01_11 = {61 62 4b 51 4d 67 57 51 76 4a 59 54 51 71 74 47 4e 7a 55 6c 72 77 64 } //1 abKQMgWQvJYTQqtGNzUlrwd
		$a_01_12 = {43 69 54 58 66 75 55 5a 59 64 62 50 58 6d 4e 6e 61 65 4d 44 45 4c 64 61 6a 6a 69 4d } //1 CiTXfuUZYdbPXmNnaeMDELdajjiM
		$a_01_13 = {5a 69 65 67 79 54 4e 43 51 47 6a 54 47 74 4e 41 63 4b 71 49 68 6b 73 76 72 41 43 4f 52 67 77 68 52 6a 68 4e } //1 ZiegyTNCQGjTGtNAcKqIhksvrACORgwhRjhN
		$a_01_14 = {67 79 53 4c 47 4d 76 4f 4d 44 42 43 72 66 6e 76 45 65 6f 4b 70 48 59 78 4f 4b 77 47 51 44 42 } //1 gySLGMvOMDBCrfnvEeoKpHYxOKwGQDB
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=5
 
}