
rule Trojan_Win32_Neoreblamy_ASP_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {6f 63 66 55 47 4e 61 65 43 69 46 72 73 53 66 4d 71 72 54 77 59 77 75 67 48 79 67 4b 73 4d } //1 ocfUGNaeCiFrsSfMqrTwYwugHygKsM
		$a_01_1 = {48 75 68 55 70 6c 4d 48 75 79 76 54 50 4f 5a 6f 6b 46 7a 54 59 63 53 55 7a 53 71 57 51 } //1 HuhUplMHuyvTPOZokFzTYcSUzSqWQ
		$a_01_2 = {57 78 47 76 6f 6b 66 42 46 4a 63 7a 4c 4f 69 59 49 7a 61 48 53 68 54 63 67 58 56 43 6b 53 6d 65 69 74 } //1 WxGvokfBFJczLOiYIzaHShTcgXVCkSmeit
		$a_01_3 = {49 62 78 58 61 65 64 4b 7a 41 61 65 50 61 73 64 78 51 72 70 57 67 66 76 5a 55 46 49 63 77 48 52 79 65 75 64 4e 78 72 } //1 IbxXaedKzAaePasdxQrpWgfvZUFIcwHRyeudNxr
		$a_01_4 = {65 65 5a 6d 6f 63 41 64 73 47 43 43 52 63 57 7a 44 58 4b 71 4b 45 67 68 52 48 6d 6c } //1 eeZmocAdsGCCRcWzDXKqKEghRHml
		$a_01_5 = {61 64 6b 48 71 4b 6f 51 65 55 46 49 54 42 53 45 6e 41 63 52 6b 66 5a 62 6d 6f 51 62 5a 4b 73 4e 67 4f } //1 adkHqKoQeUFITBSEnAcRkfZbmoQbZKsNgO
		$a_01_6 = {74 72 63 6e 4b 4a 6a 59 6d 48 58 62 62 57 44 70 4e 74 75 66 4d 71 54 57 55 6d 43 59 4c 76 6f 6d 73 6a 45 74 } //1 trcnKJjYmHXbbWDpNtufMqTWUmCYLvomsjEt
		$a_01_7 = {6d 57 61 4b 4e 50 45 71 57 4c 59 52 79 4c 44 72 47 64 71 69 78 48 59 79 4b 7a 4b 61 68 78 79 68 69 76 5a 77 6b 6c 51 5a 74 } //1 mWaKNPEqWLYRyLDrGdqixHYyKzKahxyhivZwklQZt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}