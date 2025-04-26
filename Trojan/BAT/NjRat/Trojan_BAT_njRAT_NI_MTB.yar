
rule Trojan_BAT_njRAT_NI_MTB{
	meta:
		description = "Trojan:BAT/njRAT.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {26 16 02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e ?? 00 00 04 0e 06 17 59 95 58 0e 05 } //5
		$a_81_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion
		$a_81_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d } //1 taskkill /IM
		$a_81_3 = {67 65 74 5f 41 6c 6c 6f 77 4f 6e 6c 79 46 69 70 73 41 6c 67 6f 72 69 74 68 6d 73 } //1 get_AllowOnlyFipsAlgorithms
		$a_81_4 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 2e 43 72 79 70 74 6f 43 6f 6e 66 69 67 } //1 System.Security.Cryptography.CryptoConfig
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=9
 
}