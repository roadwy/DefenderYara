
rule Trojan_BAT_CoinMiner_EC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {56 00 61 00 66 00 6c 00 79 00 61 00 31 00 32 00 33 00 2f 00 56 00 61 00 6c 00 79 00 61 00 6b 00 } //1 Vaflya123/Valyak
		$a_01_1 = {41 00 5a 00 20 00 41 00 4d 00 20 00 42 00 59 00 20 00 52 00 55 00 20 00 47 00 45 00 20 00 4b 00 5a 00 20 00 4b 00 47 00 20 00 4d 00 44 00 20 00 54 00 4a 00 20 00 54 00 4d 00 20 00 55 00 5a 00 20 00 55 00 41 00 } //1 AZ AM BY RU GE KZ KG MD TJ TM UZ UA
		$a_01_2 = {44 6c 6c 49 6d 70 6f 72 74 41 74 74 72 69 62 75 74 65 } //1 DllImportAttribute
		$a_01_3 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_01_4 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //1 Rfc2898DeriveBytes
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_7 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}