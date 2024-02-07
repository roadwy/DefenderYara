
rule Trojan_Win64_Amadey_CAV_MTB{
	meta:
		description = "Trojan:Win64/Amadey.CAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 4d 6b 74 6d 70 5c 41 6d 61 64 65 79 5c 53 74 65 61 6c 65 72 44 4c 4c } //01 00  D:\Mktmp\Amadey\StealerDLL
		$a_01_1 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  \Google\Chrome\User Data\Default\Login Data
		$a_01_2 = {5c 4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 5c 4f 70 65 72 61 20 53 74 61 62 6c 65 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  \Opera Software\Opera Stable\Login Data
		$a_01_3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  \Microsoft\Edge\User Data\Default\Login Data
		$a_01_4 = {5c 43 68 65 64 6f 74 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  \Chedot\User Data\Default\Login Data
		$a_01_5 = {5c 43 65 6e 74 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //01 00  \CentBrowser\User Data\Default\Login Data
		$a_01_6 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 22 3a } //01 00  encryptedUsername":
		$a_01_7 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 22 3a } //01 00  encryptedPassword":
		$a_01_8 = {4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 73 5c } //01 00  Monero\wallets\
		$a_01_9 = {6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //01 00  logins.json
		$a_01_10 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //00 00  SELECT origin_url, username_value, password_value FROM logins
	condition:
		any of ($a_*)
 
}