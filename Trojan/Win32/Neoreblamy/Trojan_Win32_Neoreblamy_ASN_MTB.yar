
rule Trojan_Win32_Neoreblamy_ASN_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0c 00 00 "
		
	strings :
		$a_01_0 = {59 49 67 6d 56 49 75 78 51 45 6b 4e 4d 70 65 57 47 53 48 42 69 52 59 48 61 78 71 6b 49 6a } //1 YIgmVIuxQEkNMpeWGSHBiRYHaxqkIj
		$a_01_1 = {44 44 6e 74 47 76 41 4d 41 58 72 47 4b 48 6a 77 6d 61 4a 65 4c 74 65 53 70 57 55 69 66 6e } //1 DDntGvAMAXrGKHjwmaJeLteSpWUifn
		$a_01_2 = {53 7a 64 47 61 69 74 6e 69 6b 52 55 74 44 48 68 62 66 73 71 50 51 44 6e 43 42 57 51 70 53 69 5a 4c 6b 4b 69 50 } //1 SzdGaitnikRUtDHhbfsqPQDnCBWQpSiZLkKiP
		$a_01_3 = {6b 78 6e 69 50 53 4f 72 63 63 58 64 43 66 54 42 73 41 56 74 68 64 7a 54 4d 56 47 46 72 4f 53 61 4b 59 6a 4e 6e 6e 51 } //1 kxniPSOrccXdCfTBsAVthdzTMVGFrOSaKYjNnnQ
		$a_01_4 = {52 77 46 46 47 45 68 5a 75 69 6f 69 61 4d 56 71 7a 54 78 56 66 5a 78 48 67 73 4a 59 52 49 } //1 RwFFGEhZuioiaMVqzTxVfZxHgsJYRI
		$a_01_5 = {72 4b 6f 66 63 72 63 63 55 77 69 4b 69 65 6b 72 44 74 71 6f 4c 41 5a 61 49 45 6b 5a 55 61 54 49 52 50 } //1 rKofcrccUwiKiekrDtqoLAZaIEkZUaTIRP
		$a_01_6 = {51 79 51 52 4a 43 55 49 6b 4c 42 56 4f 67 64 6b 47 73 6f 64 66 6b 47 44 67 4d 58 71 67 46 71 59 78 64 56 58 77 } //1 QyQRJCUIkLBVOgdkGsodfkGDgMXqgFqYxdVXw
		$a_01_7 = {52 45 48 78 4a 52 75 56 67 67 70 77 75 64 68 77 6f 74 6d 56 57 48 4e 77 4b 48 78 4a 54 64 4b 65 42 59 } //1 REHxJRuVggpwudhwotmVWHNwKHxJTdKeBY
		$a_01_8 = {71 56 54 58 4a 64 6a 6a 62 6f 56 43 75 6c 63 6b 6d 65 55 4d 52 4d 52 6d 79 66 54 4e 6b 68 } //1 qVTXJdjjboVCulckmeUMRMRmyfTNkh
		$a_01_9 = {75 57 68 76 6b 59 68 4f 4f 78 48 74 62 6d 50 51 55 66 63 68 65 45 70 71 41 6f 71 42 } //1 uWhvkYhOOxHtbmPQUfcheEpqAoqB
		$a_01_10 = {6f 47 4d 57 56 66 66 48 72 69 70 78 51 68 65 65 78 50 41 68 56 63 57 5a 76 72 6d 45 64 75 47 4d 4a 65 76 73 } //1 oGMWVffHripxQheexPAhVcWZvrmEduGMJevs
		$a_01_11 = {42 4e 62 65 55 66 4e 61 43 4f 48 44 41 71 55 76 54 78 72 74 66 4b 62 76 58 4d 68 45 53 65 6b 43 6c 6e 79 78 57 49 42 48 62 } //1 BNbeUfNaCOHDAqUvTxrtfKbvXMhESekClnyxWIBHb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=4
 
}