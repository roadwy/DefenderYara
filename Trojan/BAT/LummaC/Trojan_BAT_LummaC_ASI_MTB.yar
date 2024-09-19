
rule Trojan_BAT_LummaC_ASI_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {71 7a 65 6b 66 47 44 6c 4f 57 71 71 6a 46 55 62 76 56 6f 6d 74 2e 64 6c 6c } //1 qzekfGDlOWqqjFUbvVomt.dll
		$a_01_1 = {71 74 4b 58 71 75 79 79 5a 53 48 51 41 56 45 50 6f 77 2e 64 6c 6c } //1 qtKXquyyZSHQAVEPow.dll
		$a_01_2 = {65 74 7a 78 70 50 71 6c 54 44 58 52 46 78 59 55 57 73 74 6e 6d 52 57 69 7a 56 4f } //1 etzxpPqlTDXRFxYUWstnmRWizVO
		$a_01_3 = {72 74 46 51 7a 45 57 50 64 72 57 6e 6b 53 52 68 7a 63 7a 6b 4e 4f 56 70 42 46 79 } //1 rtFQzEWPdrWnkSRhzczkNOVpBFy
		$a_01_4 = {41 4d 74 4e 56 70 62 79 42 6e 4a 53 4b 6b 68 4d 4f 50 67 4d 55 56 53 66 71 52 54 4f 2e 64 6c 6c } //1 AMtNVpbyBnJSKkhMOPgMUVSfqRTO.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}