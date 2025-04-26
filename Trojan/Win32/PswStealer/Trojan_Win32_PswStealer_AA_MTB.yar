
rule Trojan_Win32_PswStealer_AA_MTB{
	meta:
		description = "Trojan:Win32/PswStealer.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 53 74 65 61 6c 65 72 5f 46 69 6c 65 5a 69 6c 6c 61 } //1 PStealer_FileZilla
		$a_01_1 = {53 74 65 61 6c 65 72 5f 54 6f 74 61 6c 43 6d 64 } //1 Stealer_TotalCmd
		$a_01_2 = {53 65 72 76 65 72 5c 50 61 73 73 77 6f 72 64 56 69 65 77 4f 6e 6c 79 } //1 Server\PasswordViewOnly
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_PswStealer_AA_MTB_2{
	meta:
		description = "Trojan:Win32/PswStealer.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 2f } //2 discord.com/api/webhooks/
		$a_01_1 = {22 75 73 65 72 6e 61 6d 65 22 3a 20 22 47 72 34 62 62 22 2c 22 63 6f 6e 74 65 6e 74 22 3a 20 22 2a 2a 54 4f 4b 45 4e 2a 2a 20 3a } //2 "username": "Gr4bb","content": "**TOKEN** :
		$a_01_2 = {43 70 6c 75 73 70 6c 75 73 54 65 73 74 2e 70 64 62 } //2 CplusplusTest.pdb
		$a_01_3 = {44 69 73 63 6f 72 64 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //1 Discord\Local Storage\leveldb
		$a_01_4 = {4c 69 67 68 74 63 6f 72 64 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //1 Lightcord\Local Storage\leveldb
		$a_01_5 = {4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 5c 4f 70 65 72 61 20 53 74 61 62 6c 65 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //1 Opera Software\Opera Stable\Local Storage\leveldb
		$a_01_6 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //1 Google\Chrome\User Data\Default\Local Storage\leveldb
		$a_01_7 = {4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //1 Microsoft\Edge\User Data\Default\Local Storage\leveldb
		$a_01_8 = {59 61 6e 64 65 78 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //1 Yandex\YandexBrowser\User Data\Default\Local Storage\leveldb
		$a_01_9 = {42 72 61 76 65 53 6f 66 74 77 61 72 65 5c 42 72 61 76 65 2d 42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //1 BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}