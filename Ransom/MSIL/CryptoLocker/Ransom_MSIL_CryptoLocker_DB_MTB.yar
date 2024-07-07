
rule Ransom_MSIL_CryptoLocker_DB_MTB{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 28 63 6f 75 6e 74 3a 20 6e 29 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files (count: n) have been encrypted
		$a_81_1 = {66 72 69 65 6e 64 6c 79 2e 63 79 62 65 72 2e 63 72 69 6d 69 6e 61 6c 40 67 6d 61 69 6c 2e 63 6f 6d } //1 friendly.cyber.criminal@gmail.com
		$a_81_2 = {52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 } //1 RECOVER__FILES
		$a_81_3 = {2e 6c 6f 63 6b 65 64 } //1 .locked
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_CryptoLocker_DB_MTB_2{
	meta:
		description = "Ransom:MSIL/CryptoLocker.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {49 45 46 4d 54 43 42 5a 54 31 56 53 49 45 5a 4a 54 45 56 54 49 45 68 42 56 6b 55 67 51 6b 56 46 54 69 42 46 54 6b 4e 53 57 56 42 55 52 55 51 } //1 IEFMTCBZT1VSIEZJTEVTIEhBVkUgQkVFTiBFTkNSWVBURUQ
		$a_81_1 = {54 6d 56 6c 5a 43 42 74 62 33 4a 6c 49 47 6c 75 5a 6d 39 79 62 57 46 30 61 57 39 75 49 47 46 69 62 33 56 30 49 45 4a 70 64 47 4e 76 61 57 34 } //1 TmVlZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IEJpdGNvaW4
		$a_81_2 = {5a 47 56 6a 63 6e 6c 77 64 46 39 7a 59 57 52 41 63 48 4a 76 64 47 39 75 62 57 46 70 62 43 35 6a 62 32 30 } //1 ZGVjcnlwdF9zYWRAcHJvdG9ubWFpbC5jb20
		$a_81_3 = {57 55 39 56 55 69 42 51 52 56 4a 54 54 30 35 42 54 43 42 4a 52 45 56 4f 56 45 6c 47 53 55 4e 42 56 45 6c 50 54 6a 6f 67 } //1 WU9VUiBQRVJTT05BTCBJREVOVElGSUNBVElPTjog
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}