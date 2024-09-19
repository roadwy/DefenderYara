
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
rule Trojan_BAT_CoinMiner_EC_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMiner.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {44 65 73 6b 74 6f 70 5c 4e 4f 2e 74 78 74 } //1 Desktop\NO.txt
		$a_81_1 = {2f 63 72 65 61 74 65 20 2f 73 63 20 4d 49 4e 55 54 45 20 2f 6d 6f 20 31 20 2f 74 6e 20 22 44 72 61 67 6f 6e 22 20 2f 74 72 } //1 /create /sc MINUTE /mo 1 /tn "Dragon" /tr
		$a_81_2 = {5c 41 70 70 44 61 74 61 5c 64 72 61 67 6f 6e 2e 65 78 65 } //1 \AppData\dragon.exe
		$a_81_3 = {5c 41 70 70 44 61 74 61 5c 78 6d 72 69 67 2e 65 78 65 } //1 \AppData\xmrig.exe
		$a_81_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_5 = {5c 41 70 70 44 61 74 61 5c 6c 6f 67 73 5c 77 61 6c 6c 65 74 73 5c } //1 \AppData\logs\wallets\
		$a_81_6 = {5c 41 70 70 44 61 74 61 5c 6c 6f 67 73 5c 63 68 72 6f 6d 65 20 65 78 74 65 6e 73 69 6f 6e 20 77 61 6c 6c 65 74 73 5c } //1 \AppData\logs\chrome extension wallets\
		$a_81_7 = {42 79 74 65 63 6f 69 6e } //1 Bytecoin
		$a_81_8 = {74 65 73 74 6f 6e 61 74 61 2e 66 72 65 65 2e 62 65 65 63 65 70 74 6f 72 } //1 testonata.free.beeceptor
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}