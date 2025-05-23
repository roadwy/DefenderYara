
rule Trojan_BAT_RedLine_MU_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 "
		
	strings :
		$a_03_0 = {03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 0c 06 72 7b 07 00 70 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 ca } //10
		$a_01_1 = {6e 00 61 00 6d 00 65 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 20 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //1 nameExtension Cookies
		$a_01_2 = {68 00 6f 00 73 00 74 00 5f 00 6b 00 65 00 79 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 } //1 host_keyAppData\Local\
		$a_01_3 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 5f 00 76 00 61 00 6c 00 75 00 65 00 } //1 encrypted_value
		$a_01_4 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //1 AppData\Local\Yandex\YandexBrowser\User Data
		$a_01_5 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 33 00 36 00 30 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //1 AppData\Local\360Browser\Browser\User Data
		$a_01_6 = {53 6b 69 70 56 65 72 69 66 69 63 61 74 69 6f 6e } //1 SkipVerification
		$a_01_7 = {44 65 63 72 79 70 74 } //1 Decrypt
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=17
 
}