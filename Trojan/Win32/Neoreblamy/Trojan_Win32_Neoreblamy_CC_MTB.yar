
rule Trojan_Win32_Neoreblamy_CC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {6e 4b 48 64 4e 56 54 54 4d 4b 74 6d 44 68 77 73 73 61 44 59 62 51 4a 68 77 6d 6d 68 5a 4d } //1 nKHdNVTTMKtmDhwssaDYbQJhwmmhZM
		$a_01_1 = {77 6d 53 46 47 47 48 75 67 4c 6a 47 56 75 45 74 52 4c 52 44 43 49 78 70 43 4f 73 57 44 51 } //1 wmSFGGHugLjGVuEtRLRDCIxpCOsWDQ
		$a_01_2 = {4a 6d 44 56 72 6f 66 42 43 63 43 52 74 52 79 48 45 6a 42 72 74 54 50 42 76 7a 4e 4d 63 6f 64 57 45 4d } //1 JmDVrofBCcCRtRyHEjBrtTPBvzNMcodWEM
		$a_01_3 = {49 6b 71 4a 75 46 4f 47 5a 79 57 59 50 65 7a 54 52 79 42 52 70 6c 6e 59 4a } //1 IkqJuFOGZyWYPezTRyBRplnYJ
		$a_01_4 = {7a 67 59 67 44 43 73 56 48 45 51 6d 47 6d 6b 6d 4e 6a 7a 73 4c 55 6e 4d 62 5a 47 73 } //1 zgYgDCsVHEQmGmkmNjzsLUnMbZGs
		$a_01_5 = {51 76 79 6a 42 51 78 63 53 64 4c 59 6f 50 49 71 7a 66 73 41 67 77 55 49 66 47 49 43 6b 47 6a 66 62 5a } //1 QvyjBQxcSdLYoPIqzfsAgwUIfGICkGjfbZ
		$a_01_6 = {65 75 4a 73 72 4c 57 55 77 71 78 47 71 61 4d 65 7a 50 75 69 6e 64 4f 66 45 42 4e 6a 41 } //1 euJsrLWUwqxGqaMezPuindOfEBNjA
		$a_01_7 = {6c 78 67 6b 65 55 6d 4b 4f 72 58 66 55 4b 50 4f 4f 77 49 50 6c 53 5a 74 64 4b 6f 55 4d 6f 76 79 } //1 lxgkeUmKOrXfUKPOOwIPlSZtdKoUMovy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}