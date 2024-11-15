
rule Trojan_Win32_Neoreblamy_ASR_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 10 00 00 "
		
	strings :
		$a_01_0 = {66 6e 57 67 72 48 70 55 4f 4b 53 50 4e 66 52 6d 71 4e 6d 76 74 70 49 5a 70 5a 4f 65 56 49 6a 48 61 4d } //1 fnWgrHpUOKSPNfRmqNmvtpIZpZOeVIjHaM
		$a_01_1 = {46 68 73 6a 61 77 45 6a 77 55 48 62 6c 79 5a 54 74 6f 56 45 47 6a 4e 4b 70 64 6d 63 53 62 } //1 FhsjawEjwUHblyZTtoVEGjNKpdmcSb
		$a_01_2 = {68 4c 6f 77 63 72 71 4d 6b 47 4a 42 63 66 74 57 47 79 50 41 79 4a 4d 5a 79 61 51 67 47 63 50 51 67 6c } //1 hLowcrqMkGJBcftWGyPAyJMZyaQgGcPQgl
		$a_01_3 = {41 4c 6f 66 52 69 6f 50 7a 4a 57 56 49 41 6d 69 53 45 57 4e 6e 72 67 4f 62 4a 70 64 49 4b } //1 ALofRioPzJWVIAmiSEWNnrgObJpdIK
		$a_01_4 = {74 6b 48 68 47 49 73 41 67 50 46 6a 64 52 68 76 4d 57 72 4b 57 55 56 50 63 4f 67 74 44 6d } //1 tkHhGIsAgPFjdRhvMWrKWUVPcOgtDm
		$a_01_5 = {41 52 55 67 71 64 52 58 72 64 4d 70 5a 6b 49 7a 76 52 50 55 69 6d 45 4b 73 75 42 44 } //1 ARUgqdRXrdMpZkIzvRPUimEKsuBD
		$a_01_6 = {63 45 74 73 56 46 6d 73 77 45 70 42 4a 4a 7a 75 6e 53 63 52 44 53 56 74 7a 48 49 43 4f 4e 58 74 6d 41 } //1 cEtsVFmswEpBJJzunScRDSVtzHICONXtmA
		$a_01_7 = {61 74 44 72 51 63 68 6b 63 78 69 57 61 61 50 5a 51 68 68 78 76 57 53 58 57 66 58 6c 4d 53 76 58 4a 4a 68 69 71 } //1 atDrQchkcxiWaaPZQhhxvWSXWfXlMSvXJJhiq
		$a_01_8 = {53 4d 4e 64 46 6f 58 6f 52 69 4b 58 4b 74 76 4d 53 64 50 79 48 51 7a 45 71 72 73 46 51 70 } //1 SMNdFoXoRiKXKtvMSdPyHQzEqrsFQp
		$a_01_9 = {52 62 51 64 45 5a 63 74 4a 53 62 54 4c 70 70 75 42 63 57 73 49 68 45 56 51 6d 64 64 54 55 7a 48 4b 75 } //1 RbQdEZctJSbTLppuBcWsIhEVQmddTUzHKu
		$a_01_10 = {42 73 64 6d 61 4a 42 7a 75 57 44 67 43 71 5a 7a 64 78 57 75 6a 41 46 57 6c 75 79 6e 4a } //1 BsdmaJBzuWDgCqZzdxWujAFWluynJ
		$a_01_11 = {76 49 62 48 58 61 62 6a 51 67 6d 77 6f 48 50 69 62 4d 77 4a 56 43 44 79 61 53 4d 4c 68 75 48 59 58 6d 54 52 } //1 vIbHXabjQgmwoHPibMwJVCDyaSMLhuHYXmTR
		$a_01_12 = {6c 56 76 6e 58 71 56 55 44 67 41 62 59 59 48 47 78 6a 70 76 4e 6c 4b 6a 68 54 56 59 72 76 } //1 lVvnXqVUDgAbYYHGxjpvNlKjhTVYrv
		$a_01_13 = {6c 78 4b 76 47 77 4d 6e 5a 74 47 44 55 4d 54 68 70 78 50 78 66 64 43 4f 4f 63 64 5a 48 6a 4e 79 79 63 } //1 lxKvGwMnZtGDUMThpxPxfdCOOcdZHjNyyc
		$a_01_14 = {71 6a 46 74 57 43 50 6c 46 45 4d 55 4a 41 77 78 52 6a 56 42 76 6c 67 42 54 4a 57 6e 4c } //1 qjFtWCPlFEMUJAwxRjVBvlgBTJWnL
		$a_01_15 = {48 6e 47 56 64 50 55 46 6f 58 47 67 6a 42 51 46 6a 54 72 65 4e 61 59 53 73 67 69 4f 77 45 70 } //1 HnGVdPUFoXGgjBQFjTreNaYSsgiOwEp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=4
 
}