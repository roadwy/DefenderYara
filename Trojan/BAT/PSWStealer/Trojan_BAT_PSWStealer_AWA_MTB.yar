
rule Trojan_BAT_PSWStealer_AWA_MTB{
	meta:
		description = "Trojan:BAT/PSWStealer.AWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {64 69 72 65 63 74 6f 72 79 54 65 6d 70 46 6f 72 43 6f 70 79 4c 6f 67 69 6e 44 61 74 61 46 69 6c 65 73 } //2 directoryTempForCopyLoginDataFiles
		$a_00_1 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //2 \Google\Chrome\User Data\Default\Login Data
		$a_00_2 = {5c 00 4b 00 2d 00 4d 00 65 00 6c 00 6f 00 6e 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //2 \K-Melon\User Data\Default\Login Data
		$a_00_3 = {5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //2 \Yandex\YandexBrowser\User Data\Default\Login Data
		$a_80_4 = {63 75 72 6c 20 2d 2d 73 73 6c 2d 6e 6f 2d 72 65 76 6f 6b 65 20 2d 58 20 50 4f 53 54 20 22 68 74 74 70 73 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //curl --ssl-no-revoke -X POST "https://api.telegram.org/bot  2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_80_4  & 1)*2) >=10
 
}